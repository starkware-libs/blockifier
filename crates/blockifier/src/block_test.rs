use starknet_api::block::BlockNumber;
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::abi::constants;
use crate::block::{pre_process_block, BlockInfo, BlockNumberHashPair};
use crate::context::ChainInfo;
use crate::state::state_api::StateReader;
use crate::test_utils::cached_state::create_test_state;
use crate::versioned_constants::VersionedConstants;

#[test]
fn test_pre_process_block() {
    let mut state = create_test_state();

    let block_number: u64 = 10;
    let block_hash = StarkFelt::from(20_u8);
    pre_process_block(
        &mut state,
        Some(BlockNumberHashPair::new(block_number, block_hash)),
        BlockInfo::default(),
        ChainInfo::default(),
        VersionedConstants::default(),
    )
    .unwrap();

    let written_hash = state.get_storage_at(
        ContractAddress::from(constants::BLOCK_HASH_CONTRACT_ADDRESS),
        StorageKey::from(block_number),
    );
    assert_eq!(written_hash.unwrap(), block_hash);

    // Test that block pre-process with block hash None fails outside the allowed block number
    // interval.
    let block_info = BlockInfo {
        block_number: BlockNumber(constants::STORED_BLOCK_HASH_BUFFER),
        ..Default::default()
    };
    assert!(
        pre_process_block(
            &mut state,
            None,
            block_info,
            ChainInfo::default(),
            VersionedConstants::default()
        )
        .is_err()
    );
}
