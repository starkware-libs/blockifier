use cairo_vm::vm::runners::cairo_runner::ResourceTracker;
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
use crate::fee::actual_cost::{ActualCost, ActualCostBuilder};
use crate::fee::gas_usage::estimate_minimal_fee;
use crate::fee::os_resources::OS_RESOURCES;
use crate::retdata;
use crate::state::cached_state::{CachedState, TransactionalState};
use crate::state::state_api::{State, StateReader};
use crate::transaction::constants;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{
    AccountTransactionContext, ResourcesMapping, TransactionExecutionInfo,
    TransactionExecutionResult,
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

    pub fn get_address_of_deploy(&self) -> Option<ContractAddress> {
        match self {
            AccountTransaction::DeployAccount(deploy_tx) => Some(deploy_tx.contract_address),
            _ => None,
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

    fn handle_validate_tx(
        &self,
        state: &mut dyn State,
        resources: &mut ExecutionResources,
        account_tx_context: &AccountTransactionContext,
        remaining_gas: &mut u64,
        block_context: &BlockContext,
        validate: bool,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        if validate {
            self.validate_tx(state, resources, account_tx_context, remaining_gas, block_context)
        } else {
            Ok(None)
        }
    }

    // TODO(Dori,1/10/2023): If/when Fees can be more than 128 bit integers, this should be updated.
    fn is_sufficient_fee_balance(
        balance_low: StarkFelt,
        balance_high: StarkFelt,
        fee: Fee,
    ) -> bool {
        // The fee is at most 128 bits, while balance is 256 bits (split into two 128 bit words).
        balance_high > StarkFelt::from(0_u8) || balance_low >= StarkFelt::from(fee.0)
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

        let (balance_low, balance_high) = state.get_fee_token_balance(
            &account_tx_context.sender_address(),
            &block_context.fee_token_address(&account_tx_context.fee_type()),
        )?;
        if !Self::is_sufficient_fee_balance(balance_low, balance_high, max_fee) {
            return Err(TransactionExecutionError::MaxFeeExceedsBalance {
                max_fee,
                balance_low,
                balance_high,
            });
        }

        Ok(())
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
        let max_fee = account_tx_context.max_fee();
        if actual_fee > max_fee {
            return Err(TransactionExecutionError::FeeTransferError { max_fee, actual_fee });
        }

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
            EntryPointExecutionContext::new_invoke(block_context, &account_tx_context);

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
    ) -> TransactionExecutionResult<ValidateExecuteCallInfo> {
        let mut resources = ExecutionResources::default();
        let validate_call_info: Option<CallInfo>;
        let execute_call_info: Option<CallInfo>;
        if matches!(self, Self::DeployAccount(_)) {
            // Handle `DeployAccount` transactions separately, due to different order of things.
            // Also, the execution context required form the `DeployAccount` execute phase is
            // validation context.
            let mut execution_context =
                EntryPointExecutionContext::new_validate(block_context, account_tx_context);
            execute_call_info =
                self.run_execute(state, &mut resources, &mut execution_context, remaining_gas)?;
            validate_call_info = self.handle_validate_tx(
                state,
                &mut resources,
                account_tx_context,
                remaining_gas,
                block_context,
                validate,
            )?;
        } else {
            let mut execution_context =
                EntryPointExecutionContext::new_invoke(block_context, account_tx_context);
            validate_call_info = self.handle_validate_tx(
                state,
                &mut resources,
                account_tx_context,
                remaining_gas,
                block_context,
                validate,
            )?;
            execute_call_info =
                self.run_execute(state, &mut resources, &mut execution_context, remaining_gas)?;
        }

        let ActualCost { actual_fee, actual_resources } = self
            .into_actual_cost_builder(block_context)
            .with_validate_call_info(&validate_call_info)
            .with_execute_call_info(&execute_call_info)
            .try_add_state_changes(state)?
            .build_for_non_reverted_tx(&resources)?;

        Ok(ValidateExecuteCallInfo::new_accepted(
            validate_call_info,
            execute_call_info,
            actual_fee,
            actual_resources,
        ))
    }

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
            EntryPointExecutionContext::new_invoke(block_context, account_tx_context);
        let account_tx_context = self.get_account_tx_context();
        // Run the validation, and if execution later fails, only keep the validation diff.
        let validate_call_info = self.handle_validate_tx(
            state,
            &mut resources,
            &account_tx_context,
            remaining_gas,
            block_context,
            validate,
        )?;

        let validate_steps = validate_call_info
            .as_ref()
            .map(|call_info| call_info.vm_resources.n_steps)
            .unwrap_or_default();

        let overhead_steps = OS_RESOURCES
            .execute_txs_inner()
            .get(&self.tx_type())
            .expect("`OS_RESOURCES` must contain all transaction types.")
            .n_steps;

        // Subtract the actual steps used for validate_tx and estimated steps required for fee
        // transfer from the steps available to the run_execute context.
        execution_context.subtract_steps(validate_steps + overhead_steps);
        let n_allotted_steps = execution_context
            .vm_run_resources
            .get_n_steps()
            .expect("The number of steps must be initialized.");

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

        match execution_result {
            Ok(execute_call_info) => {
                // When execution succeeded, calculate the actual required fee before committing the
                // transactional state. If max_fee is insufficient, revert the `run_execute` part.
                let ActualCost { actual_fee, actual_resources } =
                    actual_cost_builder_with_validation_changes
                    .clone()
                    .with_execute_call_info(&execute_call_info)
                    // Fee is determined by the sum of `validate` and `execute` state changes.
                    // Since `execute_state_changes` are not yet committed, we merge them manually
                    // with `validate_state_changes` to count correctly.
                    .try_add_state_changes(&mut execution_state)?
                    .build_for_non_reverted_tx(&execution_resources)?;

                // Check if as a result of tx execution the sender's fee token balance is maxed out,
                // so that they can't pay fee. If so, the transaction must be reverted.
                let (balance_low, balance_high) = execution_state.get_fee_token_balance(
                    &account_tx_context.sender_address(),
                    &block_context.fee_token_address(&account_tx_context.fee_type()),
                )?;
                // If the fee is charged, the balance must be sufficient for the actual fee.
                let is_maxed_out = charge_fee
                    && !Self::is_sufficient_fee_balance(balance_low, balance_high, actual_fee);
                let max_fee = account_tx_context.max_fee();

                if actual_fee > max_fee || is_maxed_out {
                    // Insufficient fee. Revert the execution and charge what is available.
                    let (final_fee, revert_error) = if actual_fee > max_fee {
                        (
                            max_fee,
                            format!(
                                "Insufficient max fee: max_fee: {max_fee:?}, actual_fee: \
                                 {actual_fee:?}",
                            ),
                        )
                    } else {
                        (actual_fee, String::from("Insufficient fee token balance"))
                    };

                    execution_state.abort();
                    let n_remaining_steps = execution_context
                        .vm_run_resources
                        .get_n_steps()
                        .expect("Invalid remaining steps in RunResources.");
                    let n_reverted_steps = n_allotted_steps - n_remaining_steps;

                    // Recalculate based on the `validate` state only in order to get the correct
                    // resources, as `execute` is reverted.
                    let ActualCost { actual_resources: final_resources, .. } =
                        actual_cost_builder_with_validation_changes
                            .build_for_reverted_tx(&execution_resources, n_reverted_steps)?;

                    return Ok(ValidateExecuteCallInfo::new_reverted(
                        validate_call_info,
                        revert_error,
                        final_fee,
                        final_resources,
                    ));
                }

                // Commit the execution.
                resources.clone_from(&execution_resources);
                execution_state.commit();
                Ok(ValidateExecuteCallInfo::new_accepted(
                    validate_call_info,
                    execute_call_info,
                    actual_fee,
                    actual_resources,
                ))
            }
            Err(_) => {
                // Error during execution. Revert.
                execution_state.abort();
                let n_remaining_steps = execution_context
                    .vm_run_resources
                    .get_n_steps()
                    .expect("The number of steps must be initialized.");
                let n_reverted_steps = n_allotted_steps - n_remaining_steps;

                // Fee is determined by the `validate` state changes since `execute` is reverted.
                let ActualCost { actual_fee, actual_resources } =
                    actual_cost_builder_with_validation_changes
                        .build_for_reverted_tx(&execution_resources, n_reverted_steps)?;

                Ok(ValidateExecuteCallInfo::new_reverted(
                    validate_call_info,
                    execution_context.error_trace(),
                    actual_fee,
                    actual_resources,
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
            final_fee,
            final_resources,
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
    final_fee: Fee,
    final_resources: ResourcesMapping,
}

impl ValidateExecuteCallInfo {
    pub fn new_accepted(
        validate_call_info: Option<CallInfo>,
        execute_call_info: Option<CallInfo>,
        final_fee: Fee,
        final_resources: ResourcesMapping,
    ) -> Self {
        Self {
            validate_call_info,
            execute_call_info,
            revert_error: None,
            final_fee,
            final_resources,
        }
    }

    pub fn new_reverted(
        validate_call_info: Option<CallInfo>,
        revert_error: String,
        final_fee: Fee,
        final_resources: ResourcesMapping,
    ) -> Self {
        Self {
            validate_call_info,
            execute_call_info: None,
            revert_error: Some(revert_error),
            final_fee,
            final_resources,
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
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let mut context =
            EntryPointExecutionContext::new_validate(block_context, account_tx_context);
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
