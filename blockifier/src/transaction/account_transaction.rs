use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{Calldata, Fee, TransactionVersion};

use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::state::state_api::State;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{
    AccountTransactionContext, TransactionExecutionInfo, TransactionExecutionResult,
};
use crate::transaction::transaction_utils::{calculate_tx_fee, execute_fee_transfer};

pub trait AccountTransaction {
    fn handle_nonce(&self, _state: &mut dyn State) -> TransactionExecutionResult<()> {
        Ok(())
    }

    fn verify_tx_version(tx_version: TransactionVersion) -> TransactionExecutionResult<()> {
        // TODO(Adi, 10/12/2022): Consider using the lazy_static crate or some other solution, so
        // the allowed_versions variable will only be constructed once.
        let allowed_versions = vec![TransactionVersion(StarkFelt::from(1))];
        if allowed_versions.contains(&tx_version) {
            Ok(())
        } else {
            Err(TransactionExecutionError::InvalidTransactionVersion {
                tx_version,
                allowed_versions,
            })
        }
    }

    fn validate_tx(
        &self,
        state: &mut dyn State,
        account_tx_context: &AccountTransactionContext,
        validate_entry_point_selector: EntryPointSelector,
        validate_entry_point_calldata: Calldata,
    ) -> TransactionExecutionResult<CallInfo> {
        let validate_call = CallEntryPoint {
            entry_point_type: EntryPointType::External,
            entry_point_selector: validate_entry_point_selector,
            calldata: validate_entry_point_calldata,
            class_hash: None,
            storage_address: account_tx_context.sender_address,
            caller_address: ContractAddress::default(),
        };

        Ok(validate_call.execute(state, account_tx_context)?)
    }

    fn execute_tx(
        self,
        state: &mut dyn State,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<CallInfo>;

    fn charge_fee(
        state: &mut dyn State,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<(Fee, CallInfo)> {
        let actual_fee = calculate_tx_fee();
        let fee_transfer_call_info = execute_fee_transfer(state, actual_fee, account_tx_context)?;

        Ok((actual_fee, fee_transfer_call_info))
    }

    fn execute(self, state: &mut dyn State)
    -> TransactionExecutionResult<TransactionExecutionInfo>;
}
