use std::sync::Arc;

use starknet_api::core::ContractAddress;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{
    Calldata, DeclareTransaction, DeployAccountTransaction, InvokeTransaction, L1HandlerTransaction,
};

use super::transaction_utils::verify_no_calls_to_other_contracts;
use crate::abi::abi_utils::selector_from_name;
use crate::block_context::BlockContext;
use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::execution::execution_utils::execute_deployment;
use crate::state::state_api::State;
use crate::transaction::constants;
use crate::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};

#[cfg(test)]
#[path = "transactions_test.rs"]
mod test;

pub trait Transaction {
    fn execute_tx(
        &self,
        state: &mut dyn State,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<Option<CallInfo>>;
}

impl Transaction for DeclareTransaction {
    fn execute_tx(
        &self,
        _state: &mut dyn State,
        _block_context: &BlockContext,
        _account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        Ok(None)
    }
}

impl Transaction for DeployAccountTransaction {
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
        verify_no_calls_to_other_contracts(&call_info, String::from("an account constructor"))?;

        Ok(Some(call_info))
    }
}

impl Transaction for InvokeTransaction {
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
}

impl Transaction for L1HandlerTransaction {
    fn execute_tx(
        &self,
        state: &mut dyn State,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let execute_call = CallEntryPoint {
            entry_point_type: EntryPointType::L1Handler,
            entry_point_selector: self.entry_point_selector,
            calldata: Calldata(Arc::clone(&self.calldata.0)),
            class_hash: None,
            storage_address: self.contract_address,
            caller_address: ContractAddress::default(),
        };

        Ok(Some(execute_call.execute(state, block_context, account_tx_context)?))
    }
}
