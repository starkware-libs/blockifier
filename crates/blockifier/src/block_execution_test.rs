use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::core::ContractAddress;
use starknet_api::state::StorageKey;
use starknet_types_core::felt::Felt;

use crate::abi::constants;
use crate::block_execution::pre_process_block;
use crate::state::state_api::StateReader;
use crate::test_utils::cached_state::create_test_state;

#[test]
fn test_pre_process_block() {
    let mut state = create_test_state();

    let block_number: u64 = 10;
    let block_hash = Felt::from(20u32);
    pre_process_block(&mut state, Some((BlockNumber(block_number), BlockHash(block_hash))))
        .unwrap();

    let written_hash = state.get_storage_at(
        ContractAddress::try_from(Felt::from_hex_unchecked(constants::BLOCK_HASH_CONTRACT_ADDRESS))
            .unwrap(),
        StorageKey::try_from(Felt::from(block_number)).unwrap(),
    );
    assert_eq!(written_hash.unwrap(), block_hash);
}
