use std::sync::Arc;

use itertools::concat;
use starknet_api::calldata;
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{
    Calldata, DeclareTransaction, DeployAccountTransaction, InvokeTransaction,
};

use crate::abi::abi_utils::selector_from_name;
use crate::block_context::BlockContext;
use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::execution::execution_utils::execute_deployment;
use crate::state::state_api::State;
use crate::transaction::constants;
use crate::transaction::execute_transaction::ExecuteTransaction;
use crate::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};

#[cfg(test)]
#[path = "transactions_test.rs"]
mod test;

impl ExecuteTransaction for DeclareTransaction {
    fn execute_tx(
        &self,
        _state: &mut dyn State,
        _block_context: &BlockContext,
        _account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        Ok(None)
    }

    fn validate_entrypoint_calldata(&self) -> Calldata {
        calldata![self.class_hash.0]
    }

    fn validate_entry_point_selector() -> EntryPointSelector {
        selector_from_name(constants::VALIDATE_DECLARE_ENTRY_POINT_NAME)
    }
}

impl ExecuteTransaction for DeployAccountTransaction {
    fn execute_tx(
        &self,
        state: &mut dyn State,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let call_info = execute_deployment(
            state,
            block_context,
            account_tx_context,
            self.class_hash,
            self.contract_address,
            ContractAddress::default(),
            self.constructor_calldata.clone(),
        )?;
        Ok(Some(call_info))
    }

    fn validate_entrypoint_calldata(&self) -> Calldata {
        let validate_calldata = concat(vec![
            vec![self.class_hash.0, self.contract_address_salt.0],
            (*self.constructor_calldata.0).clone(),
        ]);
        Calldata(Arc::new(validate_calldata))
    }

    fn validate_entry_point_selector() -> EntryPointSelector {
        selector_from_name(constants::VALIDATE_DEPLOY_ENTRY_POINT_NAME)
    }
}

impl ExecuteTransaction for InvokeTransaction {
    fn execute_tx(
        &self,
        state: &mut dyn State,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let execute_call = CallEntryPoint {
            entry_point_type: EntryPointType::External,
            entry_point_selector: selector_from_name(constants::EXECUTE_ENTRY_POINT_NAME),
            calldata: Calldata(Arc::clone(&self.calldata.0)),
            class_hash: None,
            storage_address: self.sender_address,
            caller_address: ContractAddress::default(),
        };

        Ok(Some(execute_call.execute(state, block_context, account_tx_context)?))
    }

    // Calldata for validation is the same calldata as for the execution itself.
    fn validate_entrypoint_calldata(&self) -> Calldata {
        Calldata(Arc::clone(&self.calldata.0))
    }

    fn validate_entry_point_selector() -> EntryPointSelector {
        selector_from_name(constants::VALIDATE_ENTRY_POINT_NAME)
    }
}
