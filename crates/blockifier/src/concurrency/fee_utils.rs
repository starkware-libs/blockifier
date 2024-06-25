use std::collections::HashMap;

use num_traits::ToPrimitive;
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::Fee;

use crate::context::BlockContext;
use crate::execution::call_info::CallInfo;
use crate::execution::execution_utils::stark_felt_to_felt;
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::state::cached_state::{ContractClassMapping, StateMaps};
use crate::state::state_api::UpdatableState;

#[cfg(test)]
#[path = "fee_utils_test.rs"]
mod test;

// We read account balance (sender), and sequencer balance (recipient). The balance is of type
// `Uint256`, consist of two felts (lsb, msb). Hence, storage read values =
// [account_balance, 0, sequencer_balance, 0]
pub(crate) const STORAGE_READ_SEQUENCER_BALANCE_INDICES: (usize, usize) = (2, 3);

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

pub fn add_fee_to_sequencer_balance(
    fee_token_address: ContractAddress,
    state: &mut impl UpdatableState,
    actual_fee: Fee,
    block_context: &BlockContext,
    sequencer_balance_value_low: StarkFelt,
    sequencer_balance_value_high: StarkFelt,
) {
    let sequencer_balance_low_as_u128 = stark_felt_to_felt(sequencer_balance_value_low)
        .to_u128()
        .expect("sequencer balance low should be u128");
    let sequencer_balance_high_as_u128 = stark_felt_to_felt(sequencer_balance_value_high)
        .to_u128()
        .expect("sequencer balance high should be u128");
    let (new_value_low, carry) = sequencer_balance_low_as_u128.overflowing_add(actual_fee.0);
    let (new_value_high, carry) = sequencer_balance_high_as_u128.overflowing_add(carry.into());
    assert!(
        !carry,
        "The sequencer balance overflowed when adding the fee. This should not happen."
    );
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(block_context);
    let writes = StateMaps {
        storage: HashMap::from([
            ((fee_token_address, sequencer_balance_key_low), stark_felt!(new_value_low)),
            ((fee_token_address, sequencer_balance_key_high), stark_felt!(new_value_high)),
        ]),
        ..StateMaps::default()
    };
    state.apply_writes(&writes, &ContractClassMapping::default(), &HashMap::default());
}
