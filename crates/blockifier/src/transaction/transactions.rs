use std::sync::Arc;

use starknet_api::core::ContractAddress;
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::transaction::{
    Calldata, DeclareTransaction as StarknetApiDeclareTransaction, DeployAccountTransaction,
    InvokeTransaction, L1HandlerTransaction,
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
use crate::transaction::errors::TransactionExecutionError;
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
    ) -> TransactionExecutionResult<Option<CallInfo>>;
}

#[derive(Debug)]
pub struct DeclareTransaction {
    pub starknet_api_tx: StarknetApiDeclareTransaction,
    pub contract_class: ContractClass,
}

impl<S: State> Executable<S> for DeclareTransaction {
    fn run_execute(
        &self,
        state: &mut S,
        _execution_resources: &mut ExecutionResources,
        _block_context: &BlockContext,
        _account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let class_hash = self.starknet_api_tx.class_hash();

        match state.get_contract_class(&class_hash) {
            Err(StateError::UndeclaredClassHash(_)) => {
                // Class is undeclared; declare it.
                state.set_contract_class(&class_hash, self.contract_class.clone())?;

                Ok(None)
            }
            Err(error) => Err(error).map_err(TransactionExecutionError::from),
            Ok(_) => {
                // Class is already declared.
                match self.starknet_api_tx {
                    // No class commitment, so this check is meaningless.
                    StarknetApiDeclareTransaction::V0(_) => Ok(None),
                    StarknetApiDeclareTransaction::V1(_) => Ok(None),
                    // From V2 up, cannot redeclare (i.e., make sure the leaf is uninitialized).
                    // Changing class leaf in the commitment is possible only through syscall.
                    StarknetApiDeclareTransaction::V2(_) => {
                        Err(TransactionExecutionError::DeclareTransactionError { class_hash })
                    }
                }
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
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let mut execution_context = ExecutionContext::default();
        let is_deploy_account_tx = true;
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
            is_deploy_account_tx,
        );
        let call_info = deployment_result
            .map_err(TransactionExecutionError::ContractConstructorExecutionFailed)?;
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
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let entry_point_selector = match self {
            InvokeTransaction::V0(tx) => tx.entry_point_selector,
            InvokeTransaction::V1(_) => selector_from_name(constants::EXECUTE_ENTRY_POINT_NAME),
        };
        let storage_address = self.sender_address();
        let execute_call = CallEntryPoint {
            entry_point_type: EntryPointType::External,
            entry_point_selector,
            calldata: self.calldata(),
            class_hash: None,
            code_address: None,
            storage_address,
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
        };
        let mut execution_context = ExecutionContext::default();

        execute_call
            .execute(
                state,
                execution_resources,
                &mut execution_context,
                block_context,
                account_tx_context,
            )
            .map(Some)
            .map_err(TransactionExecutionError::ExecutionError)
    }
}

impl<S: State> Executable<S> for L1HandlerTransaction {
    fn run_execute(
        &self,
        state: &mut S,
        execution_resources: &mut ExecutionResources,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let storage_address = self.contract_address;
        let execute_call = CallEntryPoint {
            entry_point_type: EntryPointType::L1Handler,
            entry_point_selector: self.entry_point_selector,
            calldata: Calldata(Arc::clone(&self.calldata.0)),
            class_hash: None,
            code_address: None,
            storage_address,
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
        };
        let mut execution_context = ExecutionContext::default();

        execute_call
            .execute(
                state,
                execution_resources,
                &mut execution_context,
                block_context,
                account_tx_context,
            )
            .map(Some)
            .map_err(TransactionExecutionError::ExecutionError)
    }
}
