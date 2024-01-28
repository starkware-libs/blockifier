use starknet_api::block::BlockNumber;
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::abi::constants;
use crate::block_context::BlockContextArgs;
use crate::block_execution::{pre_process_block, BlockNumberHashPair};
use crate::state::state_api::StateReader;
use crate::test_utils::cached_state::create_test_state;

#[test]
fn test_pre_process_block() {
    let mut state = create_test_state();

    let block_number: u64 = 10;
    let block_hash = StarkFelt::from(20_u8);
    pre_process_block(
        &mut state,
        Some(BlockNumberHashPair::new(block_number, block_hash)),
        BlockContextArgs::default(),
    )
    .unwrap();

    let written_hash = state.get_storage_at(
        ContractAddress::try_from(StarkFelt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS)).unwrap(),
        StorageKey::try_from(StarkFelt::from(block_number)).unwrap(),
    );
    assert_eq!(written_hash.unwrap(), block_hash);

    // Test that block pre-process with block hash None is successful only within the allowed
    // block number interval.
    let block_context_args = BlockContextArgs {
        block_number: BlockNumber(constants::STORED_BLOCK_HASH_BUFFER - 1),
        ..Default::default()
    };
    assert!(pre_process_block(&mut state, None, block_context_args).is_ok());
    let block_context_args = BlockContextArgs {
        block_number: BlockNumber(constants::STORED_BLOCK_HASH_BUFFER),
        ..Default::default()
    };
    assert!(pre_process_block(&mut state, None, block_context_args).is_err());
}
