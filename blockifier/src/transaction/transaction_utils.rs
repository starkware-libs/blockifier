use starknet_api::calldata;
use starknet_api::hash::StarkFelt;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{Calldata, Fee};

use crate::abi::abi_utils::get_selector_from_name;
use crate::block_context::BlockContext;
use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::state::state_api::State;
use crate::transaction::constants::TRANSFER_ENTRY_POINT_NAME;
use crate::transaction::errors::FeeTransferError;
use crate::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};

pub fn calculate_tx_fee(_block_context: &BlockContext) -> Fee {
    Fee(1)
}

pub fn execute_fee_transfer(
    state: &mut dyn State,
    actual_fee: Fee,
    block_context: &BlockContext,
    account_tx_context: &AccountTransactionContext,
) -> TransactionExecutionResult<CallInfo> {
    let max_fee = account_tx_context.max_fee;
    if actual_fee > max_fee {
        return Err(FeeTransferError::MaxFeeExceeded { max_fee, actual_fee })?;
    }

    // The least significant 128 bits of the amount transferred.
    let lsb_amount = StarkFelt::from(actual_fee.0 as u64);
    // The most significant 128 bits of the amount transferred.
    let msb_amount = StarkFelt::from(0);

    let fee_transfer_call = CallEntryPoint {
        class_hash: None,
        entry_point_type: EntryPointType::External,
        entry_point_selector: get_selector_from_name(TRANSFER_ENTRY_POINT_NAME),
        calldata: calldata![
            *block_context.sequencer_address.0.key(), // Recipient.
            lsb_amount,
            msb_amount
        ],
        storage_address: block_context.fee_token_address,
        caller_address: account_tx_context.sender_address,
    };

    Ok(fee_transfer_call.execute(state, block_context, account_tx_context)?)
}
