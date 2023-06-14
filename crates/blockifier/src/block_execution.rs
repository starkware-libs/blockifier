use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::patricia_key;
use starknet_api::state::StorageKey;

use crate::abi::constants;
use crate::state::state_api::State;

// Block pre processing.
// Writes to the block number -> hash mapping in the storage.
pub fn pre_process_block(
    state: &mut dyn State,
    n_from_current_block_number_and_hash: Option<(BlockNumber, BlockHash)>,
) {
    if let Some((block_number, block_hash)) = n_from_current_block_number_and_hash {
        state.set_storage_at(
            ContractAddress(patricia_key!(constants::BLOCK_HASH_CONTRACT_ADDRESS)),
            StorageKey::try_from(StarkFelt::from(block_number.0)).unwrap(),
            block_hash.0,
        );
    }
}
