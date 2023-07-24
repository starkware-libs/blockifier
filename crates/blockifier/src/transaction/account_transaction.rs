use std::cmp::min;

use cairo_vm::vm::runners::cairo_runner::ResourceTracker;
use itertools::concat;
use starknet_api::calldata;
use starknet_api::core::{ContractAddress, EntryPointSelector, Nonce};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, Fee, InvokeTransaction, TransactionVersion};

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants as abi_constants;
use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{
    CallEntryPoint, CallInfo, CallType, EntryPointExecutionContext, ExecutionResources, Retdata,
};
use crate::fee::fee_utils::calculate_tx_fee;
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
use crate::transaction::transaction_utils::{
    calculate_l1_gas_usage, calculate_tx_resources, update_remaining_gas,
    verify_no_calls_to_other_contracts,
};
use crate::transaction::transactions::{
    DeclareTransaction, DeployAccountTransaction, Executable, ExecutableTransaction,
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

struct ValidateExecuteCallInfo {
    validate_call_info: Option<CallInfo>,
    execute_call_info: Option<CallInfo>,
    revert_error: Option<String>,
    n_reverted_steps: usize,
}

impl ValidateExecuteCallInfo {
    pub fn new_accepted(
        validate_call_info: Option<CallInfo>,
        execute_call_info: Option<CallInfo>,
    ) -> Self {
        Self { validate_call_info, execute_call_info, revert_error: None, n_reverted_steps: 0 }
    }

    pub fn new_reverted(
        validate_call_info: Option<CallInfo>,
        revert_error: String,
        n_reverted_steps: usize,
    ) -> Self {
        Self {
            validate_call_info,
            execute_call_info: None,
            revert_error: Some(revert_error),
            n_reverted_steps,
        }
    }
}

impl AccountTransaction {
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

    pub fn max_fee(&self) -> Fee {
        match self {
            AccountTransaction::Declare(declare) => declare.tx().max_fee(),
            AccountTransaction::DeployAccount(deploy_account) => deploy_account.max_fee(),
            AccountTransaction::Invoke(invoke) => invoke.max_fee(),
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
            Self::Declare(tx) => calldata![tx.tx().class_hash().0],
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

    fn get_account_transaction_context(&self) -> AccountTransactionContext {
        match self {
            Self::Declare(tx) => {
                let tx = &tx.tx();
                AccountTransactionContext {
                    transaction_hash: tx.transaction_hash(),
                    max_fee: tx.max_fee(),
                    version: tx.version(),
                    signature: tx.signature(),
                    nonce: tx.nonce(),
                    sender_address: tx.sender_address(),
                }
            }
            Self::DeployAccount(tx) => AccountTransactionContext {
                transaction_hash: tx.transaction_hash(),
                max_fee: tx.max_fee(),
                version: tx.version(),
                signature: tx.signature(),
                nonce: tx.nonce(),
                sender_address: tx.contract_address,
            },
            Self::Invoke(tx) => AccountTransactionContext {
                transaction_hash: tx.transaction_hash(),
                max_fee: tx.max_fee(),
                version: match tx {
                    InvokeTransaction::V0(_) => TransactionVersion(StarkFelt::from(0_u8)),
                    InvokeTransaction::V1(_) => TransactionVersion(StarkFelt::from(1_u8)),
                },
                signature: tx.signature(),
                nonce: match tx {
                    InvokeTransaction::V0(_) => Nonce::default(),
                    InvokeTransaction::V1(tx_v1) => tx_v1.nonce,
                },
                sender_address: match tx {
                    InvokeTransaction::V0(tx_v0) => tx_v0.contract_address,
                    InvokeTransaction::V1(tx_v1) => tx_v1.sender_address,
                },
            },
        }
    }

    fn verify_tx_version(&self, version: TransactionVersion) -> TransactionExecutionResult<()> {
        let allowed_versions: Vec<TransactionVersion> = match self {
            // Support `Declare` of version 0 in order to allow bootstrapping of a new system.
            Self::Declare(_) => {
                vec![
                    TransactionVersion(StarkFelt::from(0_u8)),
                    TransactionVersion(StarkFelt::from(1_u8)),
                    TransactionVersion(StarkFelt::from(2_u8)),
                ]
            }
            Self::Invoke(_) => {
                vec![
                    TransactionVersion(StarkFelt::from(0_u8)),
                    TransactionVersion(StarkFelt::from(1_u8)),
                ]
            }
            _ => vec![TransactionVersion(StarkFelt::from(1_u8))],
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
        if account_tx_context.version == TransactionVersion(StarkFelt::from(0_u8)) {
            return Ok(());
        }

        let address = account_tx_context.sender_address;
        let current_nonce = state.get_nonce_at(address)?;
        if current_nonce != account_tx_context.nonce {
            return Err(TransactionExecutionError::InvalidNonce {
                address,
                expected_nonce: current_nonce,
                actual_nonce: account_tx_context.nonce,
            });
        }

        // Increment nonce.
        Ok(state.increment_nonce(address)?)
    }

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
        &self,
        state: &mut dyn State,
        resources: &mut ExecutionResources,
        remaining_gas: &mut u64,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let account_tx_context = self.get_account_transaction_context();
        let mut context =
            EntryPointExecutionContext::new_validate(block_context, &account_tx_context);
        if context.account_tx_context.is_v0() {
            return Ok(None);
        }

        let storage_address = account_tx_context.sender_address;
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
        verify_no_calls_to_other_contracts(
            &validate_call_info,
            String::from(constants::VALIDATE_ENTRY_POINT_NAME),
        )?;

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

    fn enforce_fee(&self) -> bool {
        self.max_fee() != Fee(0)
    }

    /// Checks that the account's balance covers max fee.
    fn check_fee_balance<S: StateReader>(
        &self,
        state: &mut TransactionalState<'_, S>,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<()> {
        let account_tx_context = self.get_account_transaction_context();

        // Check fee balance.
        if self.enforce_fee() {
            // Check max fee is at least the estimated constant overhead.
            let minimal_fee = estimate_minimal_fee(block_context, self)?;
            if minimal_fee > account_tx_context.max_fee {
                return Err(TransactionExecutionError::MaxFeeTooLow {
                    min_fee: minimal_fee,
                    max_fee: account_tx_context.max_fee,
                });
            }

            let (balance_low, balance_high) =
                state.get_fee_token_balance(block_context, &account_tx_context.sender_address)?;
            // TODO(Dori, 1/7/2023): If and when Fees can be more than 128 bit integers, this check
            //   should be updated.
            if balance_high == StarkFelt::from(0_u8)
                && balance_low < StarkFelt::from(account_tx_context.max_fee.0)
            {
                return Err(TransactionExecutionError::MaxFeeExceedsBalance {
                    max_fee: account_tx_context.max_fee,
                    balance_low,
                    balance_high,
                });
            }
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
        let account_tx_context = self.get_account_transaction_context();
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
        let max_fee = account_tx_context.max_fee;
        if actual_fee > max_fee {
            return Err(TransactionExecutionError::FeeTransferError { max_fee, actual_fee });
        }

        // The least significant 128 bits of the amount transferred.
        let lsb_amount = StarkFelt::from(actual_fee.0);
        // The most significant 128 bits of the amount transferred.
        let msb_amount = StarkFelt::from(0_u8);

        let storage_address = block_context.fee_token_address;
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
            caller_address: account_tx_context.sender_address,
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

    /// Runs validation and execution.
    // TODO(Zuphit, 15/7/2023): Move commit/abort to after fee transfer s.t. we can charge fee and
    // revert if running out of steps during fee transfer too.
    fn run_or_revert<S: StateReader>(
        &self,
        state: &mut TransactionalState<'_, S>,
        resources: &mut ExecutionResources,
        remaining_gas: &mut u64,
        block_context: &BlockContext,
        validate: bool,
    ) -> TransactionExecutionResult<ValidateExecuteCallInfo> {
        let account_tx_context = self.get_account_transaction_context();
        let is_v0 = account_tx_context.is_v0();
        let mut execution_context =
            EntryPointExecutionContext::new_invoke(block_context, &account_tx_context);

        // Handle `DeployAccount` transactions separately, due to different order of things.
        if matches!(self, Self::DeployAccount(_)) {
            let execute_call_info =
                self.run_execute(state, resources, &mut execution_context, remaining_gas)?;
            let validate_call_info =
                self.handle_validate_tx(state, resources, remaining_gas, block_context, validate)?;
            return Ok(ValidateExecuteCallInfo::new_accepted(
                validate_call_info,
                execute_call_info,
            ));
        }

        // V0 transactions are not revertible;
        // Reverting a Declare transaction is not currently supported in the OS.
        if is_v0 || matches!(self, Self::Declare(_)) {
            let validate_call_info =
                self.handle_validate_tx(state, resources, remaining_gas, block_context, validate)?;
            let execute_call_info =
                self.run_execute(state, resources, &mut execution_context, remaining_gas)?;
            return Ok(ValidateExecuteCallInfo::new_accepted(
                validate_call_info,
                execute_call_info,
            ));
        }

        // Run the validation, and if execution later fails, only keep the validation diff.
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

        // Subtract the actual steps used for validate_tx and estimated steps required for fee
        // transfer from the steps available to the run_execute context.
        execution_context.subtract_steps(validate_steps + overhead_steps);
        let allotted_steps = execution_context
            .vm_run_resources
            .get_n_steps()
            .expect("The number of steps must be initialized.");

        let mut execution_state = CachedState::create_transactional(state);
        match self.run_execute(
            &mut execution_state,
            resources,
            &mut execution_context,
            remaining_gas,
        ) {
            Ok(execute_call_info) => {
                execution_state.commit();
                Ok(ValidateExecuteCallInfo::new_accepted(validate_call_info, execute_call_info))
            }
            Err(_) => {
                execution_state.abort();
                let remaining_steps = execution_context
                    .vm_run_resources
                    .get_n_steps()
                    .expect("The number of steps must be initialized.");
                let n_reverted_steps = allotted_steps - remaining_steps;

                Ok(ValidateExecuteCallInfo::new_reverted(
                    validate_call_info,
                    execution_context.error_trace(),
                    n_reverted_steps,
                ))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn calculate_actual_fee_and_resources<S: StateReader>(
        &self,
        state: &mut TransactionalState<'_, S>,
        execute_call_info: &Option<CallInfo>,
        validate_call_info: &Option<CallInfo>,
        execution_resources: ExecutionResources,
        block_context: &BlockContext,
        is_reverted: bool,
        n_reverted_steps: usize,
    ) -> TransactionExecutionResult<(Fee, ResourcesMapping)> {
        let account_tx_context = self.get_account_transaction_context();

        let non_optional_call_infos = vec![validate_call_info.as_ref(), execute_call_info.as_ref()]
            .into_iter()
            .flatten()
            .collect::<Vec<&CallInfo>>();
        let l1_gas_usage = calculate_l1_gas_usage(
            &non_optional_call_infos,
            state,
            None,
            block_context.fee_token_address,
            Some(account_tx_context.sender_address),
        )?;
        let mut actual_resources =
            calculate_tx_resources(execution_resources, l1_gas_usage, self.tx_type())?;

        // Add reverted steps to actual_resources' n_steps for correct fee charge.
        *actual_resources.0.get_mut(&abi_constants::N_STEPS_RESOURCE.to_string()).unwrap() +=
            n_reverted_steps;

        let mut actual_fee = calculate_tx_fee(&actual_resources, block_context)?;

        if is_reverted || account_tx_context.max_fee == Fee(0) {
            // We cannot charge more than max_fee for reverted txs.
            actual_fee = min(actual_fee, account_tx_context.max_fee);
        }

        Ok((actual_fee, actual_resources))
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
        let account_tx_context = self.get_account_transaction_context();
        self.verify_tx_version(account_tx_context.version)?;

        let mut resources = ExecutionResources::default();
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
            n_reverted_steps,
        } =
            self.run_or_revert(state, &mut resources, &mut remaining_gas, block_context, validate)?;

        let (actual_fee, actual_resources) = self.calculate_actual_fee_and_resources(
            state,
            &execute_call_info,
            &validate_call_info,
            resources,
            block_context,
            revert_error.is_some(),
            n_reverted_steps,
        )?;

        let fee_transfer_call_info =
            self.handle_fee(state, block_context, actual_fee, charge_fee)?;

        let tx_execution_info = TransactionExecutionInfo {
            validate_call_info,
            execute_call_info,
            fee_transfer_call_info,
            actual_fee,
            actual_resources,
            revert_error,
        };
        Ok(tx_execution_info)
    }
}
