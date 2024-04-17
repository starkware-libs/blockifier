use std::collections::HashMap;

use crate::abi::abi_utils::get_fee_token_var_address;
use crate::abi::sierra_types::next_storage_key;
use crate::concurrency::versioned_state_proxy::VersionedState;
use crate::concurrency::TxIndex;
use crate::context::BlockContext;
use crate::state::cached_state::StateCache;
use crate::state::state_api::StateReader;
use crate::transaction::objects::FeeType;

pub fn thin_revalidate<S: StateReader>(
    state: &mut VersionedState<S>,
    tx_index: TxIndex,
    block_context: &BlockContext,
    state_cache: &mut StateCache,
) -> bool {
    let fee_token_address = block_context.chain_info.fee_token_address(&FeeType::Strk);
    let sequencer_address = block_context.block_info.sequencer_address;
    let sequencer_balance_key_low = get_fee_token_var_address(sequencer_address);
    let sequencer_balance_key_high = next_storage_key(&sequencer_balance_key_low).unwrap();
    let storage_initial_values = HashMap::from([
        (
            (sequencer_address, sequencer_balance_key_low),
            *state_cache
                .storage_initial_values
                .get(&(fee_token_address, sequencer_balance_key_low))
                .unwrap(),
        ),
        (
            (sequencer_address, sequencer_balance_key_high),
            *state_cache
                .storage_initial_values
                .get(&(fee_token_address, sequencer_balance_key_high))
                .unwrap(),
        ),
    ]);
    let new_state_cache = &mut StateCache {
        nonce_initial_values: HashMap::new(),
        class_hash_initial_values: HashMap::new(),
        storage_initial_values,
        compiled_class_hash_initial_values: HashMap::new(),
        nonce_writes: HashMap::new(),
        class_hash_writes: HashMap::new(),
        storage_writes: HashMap::new(),
        compiled_class_hash_writes: HashMap::new(),
    };
    state.validate_read_set(tx_index, new_state_cache)
}
