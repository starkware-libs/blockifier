use starknet_api::hash::StarkFelt;

use crate::execution::call_info::CallInfo;

#[cfg(test)]
#[path = "fee_utils_test.rs"]
mod test;

const STORAGE_READ_SEQUENCER_BALANCE_INDICES: (usize, usize) = (4, 6);
// In concurrency  run we create a call info where the sequencer balance is the actual fee.
// This function fixes the call info to have the correct sequencer balance.
pub fn fix_concurrency_fee_transfer_call_info(
    call_info: &mut CallInfo,
    sequencer_balance: StarkFelt,
) {
    assert!(
        call_info.storage_read_values.len() > 6,
        "Storage read values should have at least 7 elements"
    );
    assert_eq!(
        call_info.storage_read_values[STORAGE_READ_SEQUENCER_BALANCE_INDICES.0],
        StarkFelt::from(0_u8),
        "Sequencer balance should be the actual fee"
    );
    call_info.storage_read_values[STORAGE_READ_SEQUENCER_BALANCE_INDICES.0] = sequencer_balance;
    assert_eq!(
        call_info.storage_read_values[STORAGE_READ_SEQUENCER_BALANCE_INDICES.1],
        StarkFelt::from(0_u8),
        "Sequencer balance should be the actual fee"
    );
    call_info.storage_read_values[STORAGE_READ_SEQUENCER_BALANCE_INDICES.1] = sequencer_balance;
}
