use std::collections::HashMap;

use crate::concurrency::fee_utils::get_sequencer_address_and_keys;
use crate::concurrency::versioned_state_proxy::VersionedState;
use crate::concurrency::TxIndex;
use crate::context::TransactionContext;
use crate::state::cached_state::StateCache;
use crate::state::state_api::StateReader;

// All transactions only uptate the sequencer balance when commited,
// these changes are not visible to other transactions through execution.
// Therefore we need to check that the value read by the transaction is still valid.
// This function will return false if the transaction with tx_index read the sequencer balance
// before the previous transaction was commited.
pub fn revalidate_sequencer_balance_reads<S: StateReader>(
    state: &mut VersionedState<S>,
    tx_index: TxIndex,
    tx_context: &TransactionContext,
    read_set: &mut StateCache,
) -> bool {
    let fee_token_address = tx_context.fee_token_address();
    let (_, sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_address_and_keys(&tx_context.block_context, true);
    let mut sequencer_balance_storage_reads = HashMap::new();
    for seq_key in [sequencer_balance_key_low, sequencer_balance_key_high] {
        if let Some(value) = read_set.storage_initial_values.get(&(fee_token_address, seq_key)) {
            sequencer_balance_storage_reads.insert((fee_token_address, seq_key), *value);
        };
    }
    if sequencer_balance_storage_reads.is_empty() {
        return true;
    }

    let new_state_cache = &mut StateCache {
        storage_initial_values: sequencer_balance_storage_reads,
        ..StateCache::default()
    };
    state.validate_read_set(tx_index, new_state_cache)
}
