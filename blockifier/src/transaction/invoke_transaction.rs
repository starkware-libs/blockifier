use starknet_api::core::ContractAddress;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{Fee, InvokeTransaction};

use crate::abi::abi_utils::get_selector_from_name;
use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::state::state_api::State;
use crate::transaction::constants::{EXECUTE_ENTRY_POINT_NAME, VALIDATE_ENTRY_POINT_NAME};
use crate::transaction::objects::{
    AccountTransactionContext, ResourcesMapping, TransactionExecutionInfo,
    TransactionExecutionResult,
};
use crate::transaction::transaction_utils::{
    calculate_tx_fee, execute_fee_transfer, verify_tx_version,
};
use crate::transaction::ExecuteTransaction;

#[cfg(test)]
#[path = "invoke_transaction_test.rs"]
mod test;

pub fn validate_tx(
    tx: &InvokeTransaction,
    state: &mut dyn State,
    account_tx_context: &AccountTransactionContext,
) -> TransactionExecutionResult<CallInfo> {
    let validate_call = CallEntryPoint {
        entry_point_type: EntryPointType::External,
        entry_point_selector: get_selector_from_name(VALIDATE_ENTRY_POINT_NAME),
        // Gets the same calldata as the execution itself.
        calldata: tx.calldata.clone(),
        class_hash: None,
        storage_address: tx.sender_address,
        caller_address: ContractAddress::default(),
    };

    Ok(validate_call.execute(state, account_tx_context)?)
}

pub fn execute_tx(
    tx: &InvokeTransaction,
    state: &mut dyn State,
    account_tx_context: &AccountTransactionContext,
) -> TransactionExecutionResult<CallInfo> {
    let execute_call = CallEntryPoint {
        entry_point_type: EntryPointType::External,
        entry_point_selector: get_selector_from_name(EXECUTE_ENTRY_POINT_NAME),
        calldata: tx.calldata.clone(),
        class_hash: None,
        storage_address: tx.sender_address,
        caller_address: ContractAddress::default(),
    };

    Ok(execute_call.execute(state, account_tx_context)?)
}

pub fn charge_fee(
    tx: InvokeTransaction,
    state: &mut dyn State,
    account_tx_context: &AccountTransactionContext,
) -> TransactionExecutionResult<(Fee, CallInfo)> {
    let actual_fee = calculate_tx_fee();
    let fee_transfer_call_info =
        execute_fee_transfer(state, actual_fee, tx.max_fee, account_tx_context)?;

    Ok((actual_fee, fee_transfer_call_info))
}

impl ExecuteTransaction for InvokeTransaction {
    fn execute(
        self,
        state: &mut dyn State,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        // TODO(Adi, 10/12/2022): Consider moving the transaction version verification to the
        // TransactionVersion constructor.
        verify_tx_version(self.version)?;

        let account_tx_context = AccountTransactionContext {
            transaction_hash: self.transaction_hash,
            max_fee: self.max_fee,
            version: self.version,
            signature: self.signature.clone(),
            nonce: self.nonce,
            sender_address: self.sender_address,
        };

        // Validate transaction.
        let validate_call_info = validate_tx(&self, state, &account_tx_context)?;

        // Execute transaction.
        let execute_call_info = execute_tx(&self, state, &account_tx_context)?;

        // Charge fee.
        // TODO(Adi, 25/12/2022): Get actual resources.
        let actual_resources = ResourcesMapping::default();
        let (actual_fee, fee_transfer_call_info) = charge_fee(self, state, &account_tx_context)?;

        Ok(TransactionExecutionInfo {
            validate_call_info,
            execute_call_info: Some(execute_call_info),
            fee_transfer_call_info,
            actual_fee,
            actual_resources,
        })
    }
}
