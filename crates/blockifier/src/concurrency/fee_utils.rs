use starknet_api::hash::StarkFelt;

use crate::execution::call_info::CallInfo;

#[cfg(test)]
#[path = "fee_utils_test.rs"]
mod test;

const STORAGE_READ_SEQUENCER_BALANCE_INDEXES: (usize, usize) = (4, 6);
pub fn fix_call_info(call_info: &mut CallInfo, sequencer_balance: StarkFelt) {
    call_info.storage_read_values[STORAGE_READ_SEQUENCER_BALANCE_INDEXES.0] = sequencer_balance;
    call_info.storage_read_values[STORAGE_READ_SEQUENCER_BALANCE_INDEXES.1] = sequencer_balance;
}
