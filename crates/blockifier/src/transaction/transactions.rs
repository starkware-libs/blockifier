use std::sync::Arc;

use starknet_api::core::ContractAddress;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{
    Calldata, DeclareTransaction, DeployAccountTransaction, InvokeTransaction, L1HandlerTransaction,
};

use crate::abi::abi_utils::selector_from_name;
use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{
    CallEntryPoint, CallInfo, CallType, ExecutionContext, ExecutionResources,
};
use crate::execution::execution_utils::execute_deployment;
use crate::state::cached_state::{CachedState, MutRefState, TransactionalState};
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader};
use crate::transaction::constants;
use crate::transaction::errors::{
    ContractConstructorExecutionError, DeclareTransactionError, TransactionExecutionError,
};
use crate::transaction::objects::{
    AccountTransactionContext, TransactionExecutionInfo, TransactionExecutionResult,
};
use crate::transaction::transaction_utils::verify_no_calls_to_other_contracts;

#[cfg(test)]
#[path = "transactions_test.rs"]
mod test;

pub trait ExecutableTransaction<S: StateReader>: Sized {
    /// Executes the transaction in a transactional manner
    /// (if it fails, given state does not modify).
    fn execute(
        self,
        state: &mut CachedState<S>,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        log::debug!("Executing Transaction...");
        let mut transactional_state = CachedState::new(MutRefState::new(state));
        let execution_result = self.execute_raw(&mut transactional_state, block_context);

        match execution_result {
            Ok(value) => {
                transactional_state.commit();
                log::debug!("Transaction execution complete and committed.");
                Ok(value)
            }
            Err(error) => {
                log::warn!("Transaction execution failed with: {error}");
                transactional_state.abort();
                Err(error)
            }
        }
    }

    /// Executes the transaction in a transactional manner
    /// (if it fails, given state might become corrupted; i.e., changes until failure will appear).
    fn execute_raw(
        self,
        state: &mut TransactionalState<'_, S>,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<TransactionExecutionInfo>;
}

pub trait Executable<S: State> {
    fn run_execute(
        &self,
        state: &mut S,
        execution_resources: &mut ExecutionResources,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        // Only used for `DeclareTransaction`.
        contract_class: Option<ContractClass>,
    ) -> TransactionExecutionResult<Option<CallInfo>>;
}

impl<S: State> Executable<S> for DeclareTransaction {
    fn run_execute(
        &self,
        state: &mut S,
        _execution_resources: &mut ExecutionResources,
        _block_context: &BlockContext,
        _account_tx_context: &AccountTransactionContext,
        contract_class: Option<ContractClass>,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        match state.get_contract_class(&self.class_hash) {
            Err(StateError::UndeclaredClassHash(_)) => {
                // Class is undeclared; declare it.
                state.set_contract_class(
                    &self.class_hash,
                    contract_class.expect("Declare transaction must have a contract_class"),
                )?;

                Ok(None)
            }
            Err(error) => Err(error).map_err(TransactionExecutionError::from),
            Ok(_) => {
                // Class is already declared; cannot redeclare.
                Err(DeclareTransactionError::ClassAlreadyDeclared { class_hash: self.class_hash })
                    .map_err(TransactionExecutionError::from)
            }
        }
    }
}

impl<S: State> Executable<S> for DeployAccountTransaction {
    fn run_execute(
        &self,
        state: &mut S,
        execution_resources: &mut ExecutionResources,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        _contract_class: Option<ContractClass>,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let mut execution_context = ExecutionContext::default();
        let deployment_result = execute_deployment(
            state,
            execution_resources,
            &mut execution_context,
            block_context,
            account_tx_context,
            self.class_hash,
            self.contract_address,
            ContractAddress::default(),
            self.constructor_calldata.clone(),
        );
        let call_info = deployment_result
            .map_err(ContractConstructorExecutionError::ContractConstructorExecutionFailed)?;
        verify_no_calls_to_other_contracts(&call_info, String::from("an account constructor"))?;

        Ok(Some(call_info))
    }
}

impl<S: State> Executable<S> for InvokeTransaction {
    fn run_execute(
        &self,
        state: &mut S,
        execution_resources: &mut ExecutionResources,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        _contract_class: Option<ContractClass>,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let execute_call = CallEntryPoint {
            entry_point_type: EntryPointType::External,
            entry_point_selector: selector_from_name(constants::EXECUTE_ENTRY_POINT_NAME),
            calldata: Calldata(Arc::clone(&self.calldata.0)),
            class_hash: None,
            storage_address: self.sender_address,
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
        };
        let mut execution_context = ExecutionContext::default();

        let call_info = execute_call.execute(
            state,
            execution_resources,
            &mut execution_context,
            block_context,
            account_tx_context,
        )?;
        Ok(Some(call_info))
    }
}

impl<S: State> Executable<S> for L1HandlerTransaction {
    fn run_execute(
        &self,
        state: &mut S,
        execution_resources: &mut ExecutionResources,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        _contract_class: Option<ContractClass>,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let execute_call = CallEntryPoint {
            entry_point_type: EntryPointType::L1Handler,
            entry_point_selector: self.entry_point_selector,
            calldata: Calldata(Arc::clone(&self.calldata.0)),
            class_hash: None,
            storage_address: self.contract_address,
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
        };
        let mut execution_context = ExecutionContext::default();

        let call_info = execute_call.execute(
            state,
            execution_resources,
            &mut execution_context,
            block_context,
            account_tx_context,
        )?;
        Ok(Some(call_info))
    }
}
