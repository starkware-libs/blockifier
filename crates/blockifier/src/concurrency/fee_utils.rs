use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::abi::abi_utils::get_fee_token_var_address;
use crate::abi::sierra_types::next_storage_key;
use crate::context::BlockContext;
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
        StarkFelt::ZERO,
        "Sequencer balance should be the actual fee"
    );
    call_info.storage_read_values[STORAGE_READ_SEQUENCER_BALANCE_INDICES.0] = sequencer_balance;
    assert_eq!(
        call_info.storage_read_values[STORAGE_READ_SEQUENCER_BALANCE_INDICES.1],
        StarkFelt::ZERO,
        "Sequencer balance should be the actual fee"
    );
    call_info.storage_read_values[STORAGE_READ_SEQUENCER_BALANCE_INDICES.1] = sequencer_balance;
}

pub fn get_sequencer_address_and_keys(
    block_context: &BlockContext,
    should_panic: bool,
) -> (ContractAddress, StorageKey, StorageKey) {
    let sequencer_address = block_context.block_info.sequencer_address;
    let sequencer_balance_key_low = get_fee_token_var_address(sequencer_address);
    let sequencer_balance_key_high = if should_panic {
        next_storage_key(&sequencer_balance_key_low)
            .expect("Cannot get sequencer balance high key.")
    } else {
        next_storage_key(&sequencer_balance_key_low).unwrap()
    };
    (sequencer_address, sequencer_balance_key_low, sequencer_balance_key_high)
}
