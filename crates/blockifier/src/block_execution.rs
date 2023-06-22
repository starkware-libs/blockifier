use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::abi::constants;
use crate::state::state_api::State;

#[cfg(test)]
#[path = "block_execution_test.rs"]
pub mod test;

// Block pre-processing.
// Writes the hash of the (current_block_number - N) block under its block number in the dedicated
// contract state, where N=STORED_BLOCK_HASH_BUFFER.
pub fn pre_process_block(
    state: &mut dyn State,
    old_block_number_and_hash: Option<(BlockNumber, BlockHash)>,
) {
    if let Some((block_number, block_hash)) = old_block_number_and_hash {
        state.set_storage_at(
            ContractAddress::try_from(StarkFelt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS))
                .expect("Failed to convert `BLOCK_HASH_CONTRACT_ADDRESS` to ContractAddress."),
            StorageKey::try_from(StarkFelt::from(block_number.0))
                .expect("Failed to convert BlockNumber to StorageKey."),
            block_hash.0,
        );
    }
}
