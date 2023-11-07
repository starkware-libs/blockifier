use itertools::concat;
use starknet_api::calldata;
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, Fee, TransactionVersion};

use super::objects::HasRelatedFeeType;
use super::transactions::ValidatableTransaction;
use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants as abi_constants;
use crate::block_context::BlockContext;
use crate::execution::call_info::{CallInfo, Retdata};
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{
    CallEntryPoint, CallType, EntryPointExecutionContext, ExecutionResources,
};
use crate::fee::actual_cost::{ActualCost, ActualCostBuilder, PostExecutionReport};
use crate::fee::fee_utils::verify_can_pay_max_fee;
use crate::fee::gas_usage::estimate_minimal_fee;
use crate::retdata;
use crate::state::cached_state::{CachedState, TransactionalState};
use crate::state::state_api::{State, StateReader};
use crate::transaction::constants;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{
    AccountTransactionContext, TransactionExecutionInfo, TransactionExecutionResult,
};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transaction_utils::update_remaining_gas;
use crate::transaction::transactions::{
    DeclareTransaction, DeployAccountTransaction, Executable, ExecutableTransaction,
    InvokeTransaction,
};

#[cfg(test)]
#[path = "account_transactions_test.rs"]
mod test;

/// Represents a paid StarkNet transaction.
#[derive(Debug)]
pub enum AccountTransaction {
    Declare(DeclareTransaction),
    DeployAccount(DeployAccountTransaction),
    Invoke(InvokeTransaction),
}

impl HasRelatedFeeType for AccountTransaction {
    fn version(&self) -> TransactionVersion {
        match self {
            Self::Declare(tx) => tx.tx().version(),
            Self::DeployAccount(tx) => tx.tx().version(),
            Self::Invoke(tx) => match tx.tx {
                starknet_api::transaction::InvokeTransaction::V0(_) => TransactionVersion::ZERO,
                starknet_api::transaction::InvokeTransaction::V1(_) => TransactionVersion::ONE,
                starknet_api::transaction::InvokeTransaction::V3(_) => TransactionVersion::THREE,
            },
        }
    }

    fn is_l1_handler(&self) -> bool {
        false
    }
}

impl AccountTransaction {
    // TODO(nir, 01/11/2023): Consider instantiating CommonAccountFields in AccountTransaction.
    pub fn tx_type(&self) -> TransactionType {
        match self {
            AccountTransaction::Declare(_) => TransactionType::Declare,
            AccountTransaction::DeployAccount(_) => TransactionType::DeployAccount,
            AccountTransaction::Invoke(_) => TransactionType::InvokeFunction,
        }
    }

    fn validate_entry_point_selector(&self) -> EntryPointSelector {
        let validate_entry_point_name = match self {
            Self::Declare(_) => constants::VALIDATE_DECLARE_ENTRY_POINT_NAME,
            Self::DeployAccount(_) => constants::VALIDATE_DEPLOY_ENTRY_POINT_NAME,
            Self::Invoke(_) => constants::VALIDATE_ENTRY_POINT_NAME,
        };
        selector_from_name(validate_entry_point_name)
    }

    // Calldata for validation contains transaction fields that cannot be obtained by calling
    // `get_tx_info()`.
    fn validate_entrypoint_calldata(&self) -> Calldata {
        match self {
            Self::Declare(tx) => calldata![tx.class_hash().0],
            Self::DeployAccount(tx) => {
                let validate_calldata = concat(vec![
                    vec![tx.class_hash().0, tx.contract_address_salt().0],
                    (*tx.constructor_calldata().0).clone(),
                ]);
                Calldata(validate_calldata.into())
            }
            // Calldata for validation is the same calldata as for the execution itself.
            Self::Invoke(tx) => tx.calldata(),
        }
    }

    pub fn get_account_tx_context(&self) -> AccountTransactionContext {
        match self {
            Self::Declare(tx) => tx.get_account_tx_context(),
            Self::DeployAccount(tx) => tx.get_account_tx_context(),
            Self::Invoke(tx) => tx.get_account_tx_context(),
        }
    }

    fn verify_tx_version(&self, version: TransactionVersion) -> TransactionExecutionResult<()> {
        let allowed_versions: Vec<TransactionVersion> = match self {
            // Support `Declare` of version 0 in order to allow bootstrapping of a new system.
            Self::Declare(_) => {
                vec![
                    TransactionVersion::ZERO,
                    TransactionVersion::ONE,
                    TransactionVersion::TWO,
                    TransactionVersion::THREE,
                ]
            }
            Self::DeployAccount(_) => {
                vec![TransactionVersion::ONE, TransactionVersion::THREE]
            }
            Self::Invoke(_) => {
                vec![TransactionVersion::ZERO, TransactionVersion::ONE, TransactionVersion::THREE]
            }
        };
        if allowed_versions.contains(&version) {
            Ok(())
        } else {
            Err(TransactionExecutionError::InvalidVersion { version, allowed_versions })
        }
    }

    fn handle_nonce(
        account_tx_context: &AccountTransactionContext,
        state: &mut dyn State,
    ) -> TransactionExecutionResult<()> {
        if account_tx_context.version() == TransactionVersion::ZERO {
            return Ok(());
        }

        let address = account_tx_context.sender_address();
        let current_nonce = state.get_nonce_at(address)?;
        if current_nonce != account_tx_context.nonce() {
            return Err(TransactionExecutionError::InvalidNonce {
                address,
                expected_nonce: current_nonce,
                actual_nonce: account_tx_context.nonce(),
            });
        }

        // Increment nonce.
        Ok(state.increment_nonce(address)?)
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_validate_tx(
        &self,
        state: &mut dyn State,
        resources: &mut ExecutionResources,
        account_tx_context: &AccountTransactionContext,
        remaining_gas: &mut u64,
        block_context: &BlockContext,
        validate: bool,
        limit_steps_by_resources: bool,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        if validate {
            self.validate_tx(
                state,
                resources,
                account_tx_context,
                remaining_gas,
                block_context,
                limit_steps_by_resources,
            )
        } else {
            Ok(None)
        }
    }

    /// Checks that the account's balance covers max fee.
    fn check_fee_balance<S: StateReader>(
        &self,
        state: &mut TransactionalState<'_, S>,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<()> {
        let account_tx_context = self.get_account_tx_context();
        let max_fee = account_tx_context.max_fee();

        if !account_tx_context.enforce_fee() {
            return Ok(());
        }

        // Check max fee is at least the estimated constant overhead.
        let minimal_fee = estimate_minimal_fee(block_context, self)?;
        if minimal_fee > max_fee {
            return Err(TransactionExecutionError::MaxFeeTooLow { min_fee: minimal_fee, max_fee });
        }

        verify_can_pay_max_fee(state, &account_tx_context, block_context, max_fee)
    }

    fn handle_fee(
        &self,
        state: &mut dyn State,
        block_context: &BlockContext,
        actual_fee: Fee,
        charge_fee: bool,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        if !charge_fee || actual_fee == Fee(0) {
            // Fee charging is not enforced in some transaction simulations and tests.
            return Ok(None);
        }

        // Charge fee.
        let account_tx_context = self.get_account_tx_context();
        let fee_transfer_call_info =
            Self::execute_fee_transfer(state, block_context, account_tx_context, actual_fee)?;

        Ok(Some(fee_transfer_call_info))
    }

    fn execute_fee_transfer(
        state: &mut dyn State,
        block_context: &BlockContext,
        account_tx_context: AccountTransactionContext,
        actual_fee: Fee,
    ) -> TransactionExecutionResult<CallInfo> {
        // The least significant 128 bits of the amount transferred.
        let lsb_amount = StarkFelt::from(actual_fee.0);
        // The most significant 128 bits of the amount transferred.
        let msb_amount = StarkFelt::from(0_u8);

        // TODO(Gilad): add test that correct fee address is taken, once we add V3 test support.
        let storage_address = block_context.fee_token_address(&account_tx_context.fee_type());
        let fee_transfer_call = CallEntryPoint {
            class_hash: None,
            code_address: None,
            entry_point_type: EntryPointType::External,
            entry_point_selector: selector_from_name(constants::TRANSFER_ENTRY_POINT_NAME),
            calldata: calldata![
                *block_context.sequencer_address.0.key(), // Recipient.
                lsb_amount,
                msb_amount
            ],
            storage_address,
            caller_address: account_tx_context.sender_address(),
            call_type: CallType::Call,
            // The fee-token contract is a Cairo 0 contract, hence the initial gas is irrelevant.
            initial_gas: abi_constants::INITIAL_GAS_COST,
        };

        let mut context =
            EntryPointExecutionContext::new_invoke(block_context, &account_tx_context, true);

        Ok(fee_transfer_call.execute(state, &mut ExecutionResources::default(), &mut context)?)
    }

    fn run_execute<S: State>(
        &self,
        state: &mut S,
        resources: &mut ExecutionResources,
        context: &mut EntryPointExecutionContext,
        remaining_gas: &mut u64,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        match &self {
            Self::Declare(tx) => tx.run_execute(state, resources, context, remaining_gas),
            Self::DeployAccount(tx) => tx.run_execute(state, resources, context, remaining_gas),
            Self::Invoke(tx) => tx.run_execute(state, resources, context, remaining_gas),
        }
    }

    fn run_non_revertible<S: StateReader>(
        &self,
        state: &mut TransactionalState<'_, S>,
        account_tx_context: &AccountTransactionContext,
        remaining_gas: &mut u64,
        block_context: &BlockContext,
        validate: bool,
        charge_fee: bool,
    ) -> TransactionExecutionResult<ValidateExecuteCallInfo> {
        let mut resources = ExecutionResources::default();
        let validate_call_info: Option<CallInfo>;
        let execute_call_info: Option<CallInfo>;
        if matches!(self, Self::DeployAccount(_)) {
            // Handle `DeployAccount` transactions separately, due to different order of things.
            // Also, the execution context required form the `DeployAccount` execute phase is
            // validation context.
            let mut execution_context = EntryPointExecutionContext::new_validate(
                block_context,
                account_tx_context,
                charge_fee,
            );
            execute_call_info =
                self.run_execute(state, &mut resources, &mut execution_context, remaining_gas)?;
            validate_call_info = self.handle_validate_tx(
                state,
                &mut resources,
                account_tx_context,
                remaining_gas,
                block_context,
                validate,
                charge_fee,
            )?;
        } else {
            let mut execution_context = EntryPointExecutionContext::new_invoke(
                block_context,
                account_tx_context,
                charge_fee,
            );
            validate_call_info = self.handle_validate_tx(
                state,
                &mut resources,
                account_tx_context,
                remaining_gas,
                block_context,
                validate,
                charge_fee,
            )?;
            execute_call_info =
                self.run_execute(state, &mut resources, &mut execution_context, remaining_gas)?;
        }

        let actual_cost = self
            .into_actual_cost_builder(block_context)
            .with_validate_call_info(&validate_call_info)
            .with_execute_call_info(&execute_call_info)
            .try_add_state_changes(state)?
            .build(&resources)?;

        let post_execution_report = PostExecutionReport::generate(
            state,
            block_context,
            account_tx_context,
            &actual_cost,
            charge_fee,
        )?;
        match post_execution_report.error() {
            Some(error) => Err(error.into()),
            None => Ok(ValidateExecuteCallInfo::new_accepted(
                validate_call_info,
                execute_call_info,
                actual_cost,
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_revertible<S: StateReader>(
        &self,
        state: &mut TransactionalState<'_, S>,
        account_tx_context: &AccountTransactionContext,
        remaining_gas: &mut u64,
        block_context: &BlockContext,
        validate: bool,
        charge_fee: bool,
    ) -> TransactionExecutionResult<ValidateExecuteCallInfo> {
        let mut resources = ExecutionResources::default();
        let mut execution_context =
            EntryPointExecutionContext::new_invoke(block_context, account_tx_context, charge_fee);
        let account_tx_context = self.get_account_tx_context();
        // Run the validation, and if execution later fails, only keep the validation diff.
        let validate_call_info = self.handle_validate_tx(
            state,
            &mut resources,
            &account_tx_context,
            remaining_gas,
            block_context,
            validate,
            charge_fee,
        )?;

        let n_allotted_execution_steps = execution_context
            .subtract_validation_and_overhead_steps(&validate_call_info, &self.tx_type());

        // Save the state changes resulting from running `validate_tx`, to be used later for
        // resource and fee calculation.
        let actual_cost_builder_with_validation_changes = self
            .into_actual_cost_builder(block_context)
            .with_validate_call_info(&validate_call_info)
            .try_add_state_changes(state)?;

        // Create copies of state and resources for the execution.
        // Both will be rolled back if the execution is reverted or committed upon success.
        let mut execution_resources = resources.clone();
        let mut execution_state = CachedState::create_transactional(state);

        let execution_result = self.run_execute(
            &mut execution_state,
            &mut execution_resources,
            &mut execution_context,
            remaining_gas,
        );

        // Pre-compute cost in case of revert.
        let execution_steps_consumed =
            n_allotted_execution_steps - execution_context.n_remaining_steps();
        let revert_cost = actual_cost_builder_with_validation_changes
            .clone()
            .with_reverted_steps(execution_steps_consumed)
            .build(&resources)?;

        match execution_result {
            Ok(execute_call_info) => {
                // When execution succeeded, calculate the actual required fee before committing the
                // transactional state. If max_fee is insufficient, revert the `run_execute` part.
                let actual_cost = actual_cost_builder_with_validation_changes
                    .clone()
                    .with_execute_call_info(&execute_call_info)
                    // Fee is determined by the sum of `validate` and `execute` state changes.
                    // Since `execute_state_changes` are not yet committed, we merge them manually
                    // with `validate_state_changes` to count correctly.
                    .try_add_state_changes(&mut execution_state)?
                    .build(&execution_resources)?;

                // Post-execution checks.
                let post_execution_report = PostExecutionReport::generate(
                    &mut execution_state,
                    block_context,
                    &account_tx_context,
                    &actual_cost,
                    charge_fee,
                )?;
                match post_execution_report.error() {
                    Some(post_execution_error) => {
                        // Post-execution check failed. Revert the execution, compute the final fee
                        // to charge and recompute resources used (to be consistent with other
                        // revert case, compute resources by adding consumed execution steps to
                        // validation resources).
                        execution_state.abort();
                        Ok(ValidateExecuteCallInfo::new_reverted(
                            validate_call_info,
                            post_execution_error.to_string(),
                            ActualCost {
                                actual_fee: post_execution_report.recommended_fee(),
                                actual_resources: revert_cost.actual_resources,
                            },
                        ))
                    }
                    None => {
                        // Post-execution check passed, commit the execution.
                        execution_state.commit();
                        Ok(ValidateExecuteCallInfo::new_accepted(
                            validate_call_info,
                            execute_call_info,
                            actual_cost,
                        ))
                    }
                }
            }
            Err(_) => {
                // Error during execution. Revert.
                execution_state.abort();
                let post_execution_report = PostExecutionReport::generate(
                    state,
                    block_context,
                    &account_tx_context,
                    &revert_cost,
                    charge_fee,
                )?;
                Ok(ValidateExecuteCallInfo::new_reverted(
                    validate_call_info,
                    execution_context.error_trace(),
                    ActualCost {
                        actual_fee: post_execution_report.recommended_fee(),
                        actual_resources: revert_cost.actual_resources,
                    },
                ))
            }
        }
    }

    fn is_non_revertible(&self) -> bool {
        // Reverting a Declare or Deploy transaction is not currently supported in the OS.
        match self {
            Self::Declare(_) => true,
            Self::DeployAccount(_) => true,
            Self::Invoke(_) => {
                // V0 transactions do not have validation; we cannot deduct fee for execution. Thus,
                // invoke transactions of are non-revertible iff they are of version 0.
                self.get_account_tx_context().is_v0()
            }
        }
    }

    /// Runs validation and execution.
    fn run_or_revert<S: StateReader>(
        &self,
        state: &mut TransactionalState<'_, S>,
        remaining_gas: &mut u64,
        block_context: &BlockContext,
        validate: bool,
        charge_fee: bool,
    ) -> TransactionExecutionResult<ValidateExecuteCallInfo> {
        let account_tx_context = self.get_account_tx_context();

        if self.is_non_revertible() {
            return self.run_non_revertible(
                state,
                &account_tx_context,
                remaining_gas,
                block_context,
                validate,
                charge_fee,
            );
        }

        self.run_revertible(
            state,
            &account_tx_context,
            remaining_gas,
            block_context,
            validate,
            charge_fee,
        )
    }

    pub fn into_actual_cost_builder(&self, block_context: &BlockContext) -> ActualCostBuilder<'_> {
        ActualCostBuilder::new(block_context, self.get_account_tx_context(), self.tx_type())
    }
}

impl<S: StateReader> ExecutableTransaction<S> for AccountTransaction {
    fn execute_raw(
        self,
        state: &mut TransactionalState<'_, S>,
        block_context: &BlockContext,
        charge_fee: bool,
        validate: bool,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        let account_tx_context = self.get_account_tx_context();
        self.verify_tx_version(account_tx_context.version())?;

        let mut remaining_gas = Transaction::initial_gas();

        // Nonce and fee check should be done before running user code.
        if charge_fee {
            self.check_fee_balance(state, block_context)?;
        }
        // Handle nonce.
        Self::handle_nonce(&account_tx_context, state)?;

        // Run validation and execution.
        let ValidateExecuteCallInfo {
            validate_call_info,
            execute_call_info,
            revert_error,
            final_cost: ActualCost { actual_fee: final_fee, actual_resources: final_resources },
        } = self.run_or_revert(state, &mut remaining_gas, block_context, validate, charge_fee)?;

        let fee_transfer_call_info =
            self.handle_fee(state, block_context, final_fee, charge_fee)?;

        let tx_execution_info = TransactionExecutionInfo {
            validate_call_info,
            execute_call_info,
            fee_transfer_call_info,
            actual_fee: final_fee,
            actual_resources: final_resources,
            revert_error,
        };
        Ok(tx_execution_info)
    }
}

/// Represents a bundle of validate-execute stage execution effects.
struct ValidateExecuteCallInfo {
    validate_call_info: Option<CallInfo>,
    execute_call_info: Option<CallInfo>,
    revert_error: Option<String>,
    final_cost: ActualCost,
}

impl ValidateExecuteCallInfo {
    pub fn new_accepted(
        validate_call_info: Option<CallInfo>,
        execute_call_info: Option<CallInfo>,
        final_cost: ActualCost,
    ) -> Self {
        Self { validate_call_info, execute_call_info, revert_error: None, final_cost }
    }

    pub fn new_reverted(
        validate_call_info: Option<CallInfo>,
        revert_error: String,
        final_cost: ActualCost,
    ) -> Self {
        Self {
            validate_call_info,
            execute_call_info: None,
            revert_error: Some(revert_error),
            final_cost,
        }
    }
}

impl ValidatableTransaction for AccountTransaction {
    fn validate_tx(
        &self,
        state: &mut dyn State,
        resources: &mut ExecutionResources,
        account_tx_context: &AccountTransactionContext,
        remaining_gas: &mut u64,
        block_context: &BlockContext,
        limit_steps_by_resources: bool,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let mut context = EntryPointExecutionContext::new_validate(
            block_context,
            account_tx_context,
            limit_steps_by_resources,
        );
        if context.account_tx_context.is_v0() {
            return Ok(None);
        }

        let storage_address = account_tx_context.sender_address();
        let validate_call = CallEntryPoint {
            entry_point_type: EntryPointType::External,
            entry_point_selector: self.validate_entry_point_selector(),
            calldata: self.validate_entrypoint_calldata(),
            class_hash: None,
            code_address: None,
            storage_address,
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
            initial_gas: *remaining_gas,
        };

        let validate_call_info = validate_call
            .execute(state, resources, &mut context)
            .map_err(TransactionExecutionError::ValidateTransactionError)?;

        // Validate return data.
        let class_hash = state.get_class_hash_at(storage_address)?;
        let contract_class = state.get_compiled_contract_class(&class_hash)?;
        if let ContractClass::V1(_) = contract_class {
            // The account contract class is a Cairo 1.0 contract; the `validate` entry point should
            // return `VALID`.
            let expected_retdata = retdata![StarkFelt::try_from(constants::VALIDATE_RETDATA)?];
            if validate_call_info.execution.retdata != expected_retdata {
                return Err(TransactionExecutionError::InvalidValidateReturnData {
                    actual: validate_call_info.execution.retdata,
                });
            }
        }

        update_remaining_gas(remaining_gas, &validate_call_info);

        Ok(Some(validate_call_info))
    }
}
