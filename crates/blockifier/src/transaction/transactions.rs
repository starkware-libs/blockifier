use starknet_api::core::ContractAddress;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{DeclareTransaction, DeployAccountTransaction, InvokeTransaction};

use crate::abi::abi_utils::get_selector;
use crate::block_context::BlockContext;
use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::execution::execution_utils::execute_deployment;
use crate::state::state_api::State;
use crate::transaction::constants::EXECUTE_ENTRY_POINT_NAME;
use crate::transaction::execute_transaction::ExecuteTransaction;
use crate::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};

#[cfg(test)]
#[path = "transactions_test.rs"]
mod test;

impl ExecuteTransaction for InvokeTransaction {
    fn execute_tx(
        self,
        state: &mut dyn State,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<CallInfo> {
        let execute_call = CallEntryPoint {
            entry_point_type: EntryPointType::External,
            entry_point_selector: get_selector(EXECUTE_ENTRY_POINT_NAME),
            calldata: self.calldata.clone(),
            class_hash: None,
            storage_address: self.sender_address,
            caller_address: ContractAddress::default(),
        };

        Ok(execute_call.execute(state, block_context, account_tx_context)?)
    }
}

impl ExecuteTransaction for DeclareTransaction {
    fn execute_tx(
        self,
        _state: &mut dyn State,
        _block_context: &BlockContext,
        _account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<CallInfo> {
        Ok(CallInfo::default())
    }
}

impl ExecuteTransaction for DeployAccountTransaction {
    fn execute_tx(
        self,
        state: &mut dyn State,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<CallInfo> {
        let call_info = execute_deployment(
            state,
            block_context,
            account_tx_context,
            self.class_hash,
            self.contract_address,
            ContractAddress::default(),
            self.constructor_calldata,
        )?;
        Ok(call_info)
    }
}
