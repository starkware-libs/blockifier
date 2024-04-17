use std::collections::HashMap;
use std::sync::Arc;

use crate::abi::abi_utils::get_fee_token_var_address;
use crate::abi::sierra_types::next_storage_key;
use crate::concurrency::versioned_state_proxy::VersionedState;
use crate::concurrency::TxIndex;
use crate::context::TransactionContext;
use crate::state::cached_state::StateCache;
use crate::state::state_api::StateReader;

pub fn thin_revalidate<S: StateReader>(
    state: &mut VersionedState<S>,
    tx_index: TxIndex,
    tx_context: Arc<TransactionContext>,
    read_set: &mut StateCache,
) -> bool {
    let fee_token_address = tx_context.fee_token_address();
    let sequencer_address = tx_context.block_context.block_info.sequencer_address;
    let sequencer_balance_key_low = get_fee_token_var_address(sequencer_address);
    let sequencer_balance_key_high = next_storage_key(&sequencer_balance_key_low).unwrap();
    let mut storage_initial_values = HashMap::new();
    for seq_key in [sequencer_balance_key_low, sequencer_balance_key_high] {
        match read_set.storage_initial_values.get(&(fee_token_address, seq_key)) {
            Some(value) => storage_initial_values.insert((fee_token_address, seq_key), *value),
            None => None,
        };
    }

    let new_state_cache = &mut StateCache { storage_initial_values, ..StateCache::default() };
    state.validate_read_set(tx_index, new_state_cache)
}
