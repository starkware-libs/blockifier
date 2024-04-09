use starknet_api::hash::StarkFelt;

use crate::execution::call_info::CallInfo;
#[cfg(test)]
#[path = "fee_utils_test.rs"]
mod test;

// We read account balance (sender), and sequencer balance (recipient). The balance is of type
// `Uint256`, consist of two felts (lsb, msb). Hence, storage read values =
// [account_balance, 0, sequencer_balance, 0]
const STORAGE_READ_SEQUENCER_BALANCE_INDICES: (usize, usize) = (2, 3);

// Completes the fee transfer execution by fixing the call info to have the correct sequencer
// balance. In concurrency mode, the fee transfer is executed with a false (constant) sequencer
// balance. This affects the call info.
pub fn fill_sequencer_balance_reads(
    fee_transfer_call_info: &mut CallInfo,
    sequencer_balance_low: StarkFelt,
    sequencer_balance_high: StarkFelt,
) {
    let storage_read_values = &mut fee_transfer_call_info.storage_read_values;
    assert_eq!(storage_read_values.len(), 4, "Storage read values should have 4 elements");

    let (low_index, high_index) = STORAGE_READ_SEQUENCER_BALANCE_INDICES;
    for index in [low_index, high_index] {
        assert_eq!(storage_read_values[index], StarkFelt::ZERO, "Sequencer balance should be zero");
    }
    storage_read_values[low_index] = sequencer_balance_low;
    storage_read_values[high_index] = sequencer_balance_high;
}
