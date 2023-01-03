use starknet_api::core::ContractAddress;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::InvokeTransaction;

use crate::abi::abi_utils::get_selector_from_name;
use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::state::state_api::State;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants::{EXECUTE_ENTRY_POINT_NAME, VALIDATE_ENTRY_POINT_NAME};
use crate::transaction::objects::{
    AccountTransactionContext, ResourcesMapping, TransactionExecutionInfo,
    TransactionExecutionResult,
};

#[cfg(test)]
#[path = "invoke_transaction_test.rs"]
mod test;

impl AccountTransaction for InvokeTransaction {
    fn execute_tx(
        self,
        state: &mut dyn State,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<CallInfo> {
        let execute_call = CallEntryPoint {
            entry_point_type: EntryPointType::External,
            entry_point_selector: get_selector_from_name(EXECUTE_ENTRY_POINT_NAME),
            calldata: self.calldata.clone(),
            class_hash: None,
            storage_address: self.sender_address,
            caller_address: ContractAddress::default(),
        };

        Ok(execute_call.execute(state, account_tx_context)?)
    }

    fn execute(
        self,
        state: &mut dyn State,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        Self::verify_tx_version(self.version)?;
        Self::handle_nonce(&self, state)?;

        let account_tx_context = AccountTransactionContext {
            transaction_hash: self.transaction_hash,
            max_fee: self.max_fee,
            version: self.version,
            signature: self.signature.clone(),
            nonce: self.nonce,
            sender_address: self.sender_address,
        };

        // Validate transaction.
        let validate_call_info = Self::validate_tx(
            &self,
            state,
            &account_tx_context,
            get_selector_from_name(VALIDATE_ENTRY_POINT_NAME),
            // Gets the same calldata as the execution itself.
            self.calldata.clone(),
        )?;

        // Execute transaction.
        let execute_call_info = Self::execute_tx(self, state, &account_tx_context)?;

        // Charge fee.
        // TODO(Adi, 25/12/2022): Get actual resources.
        let actual_resources = ResourcesMapping::default();
        let (actual_fee, fee_transfer_call_info) = Self::charge_fee(state, &account_tx_context)?;

        Ok(TransactionExecutionInfo {
            validate_call_info,
            execute_call_info: Some(execute_call_info),
            fee_transfer_call_info,
            actual_fee,
            actual_resources,
        })
    }
}
