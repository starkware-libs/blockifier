use starknet_api::hash::StarkFelt;

use crate::execution::call_info::CallInfo;
#[cfg(test)]
#[path = "fee_utils_test.rs"]
mod test;

// In concurrency mode we execute the fee transfer with false sequencer balance values.
// This function fixes the call info to have the correct sequencer balance.
pub fn fill_sequencer_balance_reads(
    fee_transfer_call_info: &mut CallInfo,
    sequencer_balance_low: StarkFelt,
    sequencer_balance_high: StarkFelt,
) {
    let sequencer_balance_indecies = if fee_transfer_call_info.storage_read_values.len() == 4 {
        2..4
    } else {
        assert_eq!(
            fee_transfer_call_info.storage_read_values.len(),
            8,
            "Storage read values should have 8 elements"
        );
        4..8
    };

    // We read account balance (sender), write (which starts with read) the account balance. We then
    // do the same for the sequencer balance (recipient). The balance is of type `Uint256`,
    // consist of two felts (lsb, msb). Hence, storage read values = [account_balance, 0,
    // account_balance, 0, sequencer_balance, 0, sequencer_balance, 0]
    for index in sequencer_balance_indecies {
        assert_eq!(
            fee_transfer_call_info.storage_read_values[index],
            StarkFelt::ZERO,
            "Sequencer balance should be the zero"
        );
        fee_transfer_call_info.storage_read_values[index] =
            if index % 2 == 0 { sequencer_balance_low } else { sequencer_balance_high };
    }
}
