use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::abi::constants;
use crate::block_execution::{pre_process_block, BlockContextArgs, BlockNumberAndHash};
use crate::state::state_api::StateReader;
use crate::test_utils::cached_state::create_test_state;

#[test]
fn test_pre_process_block() {
    let mut state = create_test_state();

    let block_number: u64 = 10;
    let block_hash = StarkFelt::from(20u32);
    pre_process_block(
        &mut state,
        Some(BlockNumberAndHash::new(BlockNumber(block_number), BlockHash(block_hash))),
        BlockContextArgs::default(),
    )
    .unwrap();

    let written_hash = state.get_storage_at(
        ContractAddress::try_from(StarkFelt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS)).unwrap(),
        StorageKey::try_from(StarkFelt::from(block_number)).unwrap(),
    );
    assert_eq!(written_hash.unwrap(), block_hash);

    // Test that the function returns error when old_block_number_and_hash is None and block_number
    // >= 10
    let block_context_args =
        BlockContextArgs { block_number: BlockNumber(10), ..Default::default() };
    assert!(pre_process_block(&mut state, None, block_context_args).is_err());
}
