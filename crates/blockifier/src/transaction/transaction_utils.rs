use starknet_api::transaction::{Fee, L1HandlerTransaction};

use crate::block_context::BlockContext;
use crate::execution::entry_point::CallInfo;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::TransactionExecutionResult;

pub trait HasPayloadSize {
    fn get_payload_size(&self) -> u64;
}

impl HasPayloadSize for L1HandlerTransaction {
    fn get_payload_size(&self) -> u64 {
        (self.calldata.0.len() as u64) - 1
    }
}

pub fn calculate_tx_fee(_block_context: &BlockContext) -> Fee {
    Fee(2)
}

pub fn verify_no_calls_to_other_contracts(
    call_info: &CallInfo,
    entry_point_kind: String,
) -> TransactionExecutionResult<()> {
    let invoked_contract_address = call_info.call.storage_address;
    if call_info
        .into_iter()
        .any(|inner_call| inner_call.call.storage_address != invoked_contract_address)
    {
        return Err(TransactionExecutionError::UnauthorizedInnerCall { entry_point_kind });
    }

    Ok(())
}
