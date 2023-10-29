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
use crate::fee::fee_utils::{can_pay_fee, verify_can_pay_max_fee};
use crate::fee::gas_usage::estimate_minimal_fee;
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

<<<<<<< HEAD
    fn handle_validate_tx(
||||||| 6295b3d
    fn validate_tx(
=======
    fn handle_validate_tx(
        &self,
        state: &mut dyn State,
        resources: &mut ExecutionResources,
        remaining_gas: &mut u64,
        block_context: &BlockContext,
        validate: bool,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        if validate {
            self.validate_tx(state, resources, remaining_gas, block_context)
        } else {
            Ok(None)
        }
    }

    fn validate_tx(
>>>>>>> origin/main-v0.12.3
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

    /// After successful execution and fee computation, checks that the sender can pay the fee.
    /// Returns the actual fee to pay and an optional revert error (if revert is needed).
    fn post_execution_final_fee_and_error<S: StateReader>(
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        execution_state: &mut TransactionalState<'_, S>,
        post_execute_fee: Fee,
        charge_fee: bool,
    ) -> TransactionExecutionResult<(Fee, Option<String>)> {
        let max_fee = account_tx_context.max_fee();
        let can_pay =
            can_pay_fee(execution_state, account_tx_context, block_context, post_execute_fee)?;

        if charge_fee && (post_execute_fee > max_fee || !can_pay) {
            // Insufficient fee. Revert the execution and charge what is available.
            if post_execute_fee > max_fee {
                Ok((
                    max_fee,
                    Some(format!(
                        "Insufficient max fee: max_fee: {max_fee:?}, actual_fee: \
                         {post_execute_fee:?}",
                    )),
                ))
            } else {
                Ok((post_execute_fee, Some(String::from("Insufficient fee token balance"))))
            }
        } else {
            Ok((post_execute_fee, None))
        }
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
<<<<<<< HEAD
        validate: bool,
||||||| 6295b3d
        mut execution_context: EntryPointExecutionContext,
=======
        mut execution_context: EntryPointExecutionContext,
        validate: bool,
>>>>>>> origin/main-v0.12.3
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
<<<<<<< HEAD
                self.run_execute(state, &mut resources, &mut execution_context, remaining_gas)?;
            validate_call_info = self.handle_validate_tx(
                state,
                &mut resources,
                account_tx_context,
                remaining_gas,
                block_context,
                validate,
            )?;
||||||| 6295b3d
                self.run_execute(state, resources, &mut execution_context, remaining_gas)?;
            validate_call_info =
                self.validate_tx(state, resources, remaining_gas, block_context)?;
=======
                self.run_execute(state, resources, &mut execution_context, remaining_gas)?;
            validate_call_info =
                self.handle_validate_tx(state, resources, remaining_gas, block_context, validate)?;
>>>>>>> origin/main-v0.12.3
        } else {
<<<<<<< HEAD
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
||||||| 6295b3d
            validate_call_info =
                self.validate_tx(state, resources, remaining_gas, block_context)?;
=======
            validate_call_info =
                self.handle_validate_tx(state, resources, remaining_gas, block_context, validate)?;
>>>>>>> origin/main-v0.12.3
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

    #[allow(clippy::too_many_arguments)]
    fn run_revertible<S: StateReader>(
        &self,
        state: &mut TransactionalState<'_, S>,
        account_tx_context: &AccountTransactionContext,
        remaining_gas: &mut u64,
        block_context: &BlockContext,
<<<<<<< HEAD
        validate: bool,
        charge_fee: bool,
||||||| 6295b3d
        mut execution_context: EntryPointExecutionContext,
=======
        mut execution_context: EntryPointExecutionContext,
        charge_fee: bool,
        validate: bool,
>>>>>>> origin/main-v0.12.3
    ) -> TransactionExecutionResult<ValidateExecuteCallInfo> {
        let mut resources = ExecutionResources::default();
        let mut execution_context =
            EntryPointExecutionContext::new_invoke(block_context, account_tx_context);
        let account_tx_context = self.get_account_tx_context();
        // Run the validation, and if execution later fails, only keep the validation diff.
<<<<<<< HEAD
        let validate_call_info = self.handle_validate_tx(
            state,
            &mut resources,
            &account_tx_context,
            remaining_gas,
            block_context,
            validate,
        )?;
||||||| 6295b3d
        let validate_call_info =
            self.validate_tx(state, resources, remaining_gas, block_context)?;
        let validate_steps = validate_call_info.as_ref().unwrap().vm_resources.n_steps;
        let overhead_steps = OS_RESOURCES.execute_txs_inner().get(&self.tx_type()).unwrap().n_steps;
=======
        let validate_call_info =
            self.handle_validate_tx(state, resources, remaining_gas, block_context, validate)?;
        let validate_steps = if validate {
            validate_call_info
                .as_ref()
                .expect("`validate` call info cannot be `None`.")
                .vm_resources
                .n_steps
        } else {
            0
        };
        let overhead_steps = OS_RESOURCES
            .execute_txs_inner()
            .get(&self.tx_type())
            .expect("`OS_RESOURCES` must contain all transaction types.")
            .n_steps;
>>>>>>> origin/main-v0.12.3

<<<<<<< HEAD
        let n_allotted_execution_steps = execution_context
            .subtract_validation_and_overhead_steps(&validate_call_info, &self.tx_type());
||||||| 6295b3d
        // Subtract the actual steps used for validate_tx and estimated steps required for fee
        // transfer from the steps available to the run_execute context.
        execution_context.subtract_steps(validate_steps + overhead_steps);
        let n_allotted_steps = execution_context.vm_run_resources.get_n_steps().unwrap();
=======
        // Subtract the actual steps used for validate_tx and estimated steps required for fee
        // transfer from the steps available to the run_execute context.
        execution_context.subtract_steps(validate_steps + overhead_steps);
        let n_allotted_steps = execution_context
            .vm_run_resources
            .get_n_steps()
            .expect("The number of steps must be initialized.");
>>>>>>> origin/main-v0.12.3

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

                // Post-execution: check senders ability and willingness to pay the fee.
                let (reverted_tx_fee, revert_error) = Self::post_execution_final_fee_and_error(
                    block_context,
                    &account_tx_context,
                    &mut execution_state,
                    actual_fee,
                    charge_fee,
                )?;

<<<<<<< HEAD
                // Revert or accept depending on result of post-execution check.
                if let Some(revert_error) = revert_error {
||||||| 6295b3d
                // Check if as a result of tx execution the sender's fee token balance is maxed out,
                // so that they can't pay fee. If so, the transaction must be reverted.
                let (balance_low, balance_high) = execution_state
                    .get_fee_token_balance(block_context, &account_tx_context.sender_address)?;
                let is_maxed_out =
                    !Self::is_sufficient_fee_balance(balance_low, balance_high, actual_fee);
                let max_fee = account_tx_context.max_fee;

                if actual_fee > max_fee || is_maxed_out {
                    // Insufficient fee. Revert the execution and charge what is available.
                    let (final_fee, revert_error) = if actual_fee > max_fee {
                        (
                            max_fee,
                            format!(
                                "Insufficient max fee: max_fee: {:?}, actual_fee: {:?}",
                                max_fee, actual_fee
                            ),
                        )
                    } else {
                        (actual_fee, String::from("Insufficient fee token balance"))
                    };

=======
                // Check if as a result of tx execution the sender's fee token balance is maxed out,
                // so that they can't pay fee. If so, the transaction must be reverted.
                let (balance_low, balance_high) = execution_state
                    .get_fee_token_balance(block_context, &account_tx_context.sender_address)?;
                let is_maxed_out =
                    !Self::is_sufficient_fee_balance(balance_low, balance_high, actual_fee);
                let max_fee = account_tx_context.max_fee;

                if charge_fee && (actual_fee > max_fee || is_maxed_out) {
                    // Insufficient fee. Revert the execution and charge what is available.
                    let (final_fee, revert_error) = if actual_fee > max_fee {
                        (
                            max_fee,
                            format!(
                                "Insufficient max fee: max_fee: {:?}, actual_fee: {:?}",
                                max_fee, actual_fee
                            ),
                        )
                    } else {
                        (actual_fee, String::from("Insufficient fee token balance"))
                    };

>>>>>>> origin/main-v0.12.3
                    execution_state.abort();
                    let n_reverted_steps =
                        n_allotted_execution_steps - execution_context.n_remaining_steps();

                    // Recalculate based on the `validate` state only in order to get the correct
                    // resources, as `execute` is reverted.
                    let ActualCost { actual_resources: reverted_tx_resources, .. } =
                        actual_cost_builder_with_validation_changes
                            .build_for_reverted_tx(&resources, n_reverted_steps)?;

                    Ok(ValidateExecuteCallInfo::new_reverted(
                        validate_call_info,
                        revert_error,
                        reverted_tx_fee,
                        reverted_tx_resources,
                    ))
                } else {
                    // Commit the execution.
                    execution_state.commit();
                    Ok(ValidateExecuteCallInfo::new_accepted(
                        validate_call_info,
                        execute_call_info,
                        actual_fee,
                        actual_resources,
                    ))
                }
            }
            Err(_) => {
                // Error during execution. Revert.
                execution_state.abort();
<<<<<<< HEAD
                let n_reverted_steps =
                    n_allotted_execution_steps - execution_context.n_remaining_steps();
||||||| 6295b3d
                let n_remaining_steps = execution_context.vm_run_resources.get_n_steps().unwrap();
                let n_reverted_steps = n_allotted_steps - n_remaining_steps;
=======
                let n_remaining_steps = execution_context
                    .vm_run_resources
                    .get_n_steps()
                    .expect("The number of steps must be initialized.");
                let n_reverted_steps = n_allotted_steps - n_remaining_steps;
>>>>>>> origin/main-v0.12.3

                // Fee is determined by the `validate` state changes since `execute` is reverted.
                let ActualCost { actual_fee, actual_resources } =
                    actual_cost_builder_with_validation_changes
                        .build_for_reverted_tx(&resources, n_reverted_steps)?;

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
<<<<<<< HEAD
        validate: bool,
        charge_fee: bool,
||||||| 6295b3d
=======
        charge_fee: bool,
        validate: bool,
>>>>>>> origin/main-v0.12.3
    ) -> TransactionExecutionResult<ValidateExecuteCallInfo> {
        let account_tx_context = self.get_account_tx_context();

        if self.is_non_revertible() {
            return self.run_non_revertible(
                state,
                &account_tx_context,
                remaining_gas,
                block_context,
<<<<<<< HEAD
                validate,
||||||| 6295b3d
                execution_context,
=======
                execution_context,
                validate,
>>>>>>> origin/main-v0.12.3
            );
        }

<<<<<<< HEAD
        self.run_revertible(
            state,
            &account_tx_context,
            remaining_gas,
            block_context,
            validate,
            charge_fee,
        )
||||||| 6295b3d
        self.run_revertible(state, resources, remaining_gas, block_context, execution_context)
=======
        self.run_revertible(
            state,
            resources,
            remaining_gas,
            block_context,
            execution_context,
            charge_fee,
            validate,
        )
>>>>>>> origin/main-v0.12.3
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
<<<<<<< HEAD
        } = self.run_or_revert(state, &mut remaining_gas, block_context, validate, charge_fee)?;
||||||| 6295b3d
        } = self.run_or_revert(state, &mut resources, &mut remaining_gas, block_context)?;
=======
        } = self.run_or_revert(
            state,
            &mut resources,
            &mut remaining_gas,
            block_context,
            charge_fee,
            validate,
        )?;
>>>>>>> origin/main-v0.12.3

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
