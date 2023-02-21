use std::sync::Arc;

use starknet_api::core::ContractAddress;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{
    Calldata, DeclareTransaction, DeployAccountTransaction, InvokeTransaction, L1HandlerTransaction,
};

use crate::abi::abi_utils::selector_from_name;
use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::execution::execution_utils::execute_deployment;
use crate::state::state_api::State;
use crate::transaction::constants;
use crate::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};
use crate::transaction::transaction_utils::verify_no_calls_to_other_contracts;

#[cfg(test)]
#[path = "transactions_test.rs"]
mod test;

pub trait Executable {
    fn execute(
        &self,
        state: &mut dyn State,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        // Only used for `DeclareTransaction`.
        contract_class: Option<ContractClass>,
    ) -> TransactionExecutionResult<Option<CallInfo>>;
}

impl Executable for DeclareTransaction {
    fn execute(
        &self,
        state: &mut dyn State,
        _block_context: &BlockContext,
        _account_tx_context: &AccountTransactionContext,
        contract_class: Option<ContractClass>,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        state.set_contract_class(
            &self.class_hash,
            contract_class.expect("Declare transaction must have a contract_class"),
        )?;
        Ok(None)
    }
}

impl Executable for DeployAccountTransaction {
    fn execute(
        &self,
        state: &mut dyn State,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        _contract_class: Option<ContractClass>,
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

impl Executable for InvokeTransaction {
    fn execute(
        &self,
        state: &mut dyn State,
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
        };

        Ok(Some(execute_call.execute(state, block_context, account_tx_context)?))
    }
}

impl Executable for L1HandlerTransaction {
    fn execute(
        &self,
        state: &mut dyn State,
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
        };

        Ok(Some(execute_call.execute(state, block_context, account_tx_context)?))
    }
}
