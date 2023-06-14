use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::patricia_key;
use starknet_api::state::StorageKey;

use crate::abi::constants;
use crate::block_execution::pre_process_block;
use crate::state::state_api::StateReader;
use crate::test_utils::create_test_state;

#[test]
fn test_pre_process_block() {
    let mut state = create_test_state();

    let block_number: u64 = 10;
    let block_hash = StarkFelt::from(20u32);
    pre_process_block(&mut state, Some((BlockNumber(block_number), BlockHash(block_hash))));

    let written_hash = state.get_storage_at(
        ContractAddress(patricia_key!(constants::BLOCK_HASH_CONTRACT_ADDRESS)),
        StorageKey::try_from(StarkFelt::from(block_number)).unwrap(),
    );
    assert_eq!(written_hash.unwrap(), block_hash);
}
