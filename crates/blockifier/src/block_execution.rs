use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::abi::constants;
use crate::state::state_api::State;

#[cfg(test)]
#[path = "block_execution_test.rs"]
pub mod test;

// Block pre processing.
// Writes to the block number -> hash mapping in the storage.
pub fn pre_process_block(
    state: &mut dyn State,
    n_from_current_block_number_and_hash: Option<(BlockNumber, BlockHash)>,
) {
    if let Some((block_number, block_hash)) = n_from_current_block_number_and_hash {
        state.set_storage_at(
            ContractAddress::try_from(StarkFelt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS))
                .unwrap(),
            StorageKey::try_from(StarkFelt::from(block_number.0))
                .expect("Failed to convert BlockNumber to StorageKey."),
            block_hash.0,
        );
    }
}
