use std::collections::HashMap;

use crate::concurrency::versioned_state_proxy::VersionedStateProxy;
use crate::context::TransactionContext;
use crate::fee::fee_utils::get_sequencer_address_and_keys;
use crate::state::cached_state::StateMaps;
use crate::state::state_api::StateReader;

// All transactions only uptate the sequencer balance when commited,
// these changes are not visible to other transactions through execution.
// Therefore we need to check that the value read by the transaction is still valid.
// This function is relevant for transactions that read the sequencer balance before the fee
// transfer
pub fn revalidate_sequencer_balance_reads<S: StateReader>(
    versioned_state: &VersionedStateProxy<S>,
    tx_context: &TransactionContext,
    read_set: &StateMaps,
) -> bool {
    let fee_token_address = tx_context.fee_token_address();
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_address_and_keys(&tx_context.block_context);
    let mut sequencer_balance_storage_reads = HashMap::new();
    for seq_key in [sequencer_balance_key_low, sequencer_balance_key_high] {
        if let Some(value) = read_set.storage.get(&(fee_token_address, seq_key)) {
            sequencer_balance_storage_reads.insert((fee_token_address, seq_key), *value);
        };
    }

    if sequencer_balance_storage_reads.is_empty() {
        return true;
    }

    let new_state_cache =
        &mut StateMaps { storage: sequencer_balance_storage_reads, ..StateMaps::default() };
    versioned_state
        .state
        .lock()
        .expect("failed to lock state in revalidate_sequencer_balance_reads")
        .validate_read_set(versioned_state.tx_index, new_state_cache)
}
