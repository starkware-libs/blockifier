use starknet_api::block::BlockNumber;
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::abi::constants;
use crate::blockifier::block::{pre_process_block, BlockInfo, BlockNumberHashPair};
use crate::bouncer::BouncerConfig;
use crate::context::ChainInfo;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{CairoVersion, BALANCE};
use crate::versioned_constants::VersionedConstants;

#[test]
fn test_pre_process_block() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    // Test the positive flow of pre_process_block inside the allowed block number interval
    let block_number = constants::STORED_BLOCK_HASH_BUFFER;
    let block_hash = StarkFelt::from(20_u8);
    let mut block_info = BlockInfo::create_for_testing();
    block_info.block_number = BlockNumber(block_number);
    pre_process_block(
        &mut state,
        Some(BlockNumberHashPair::new(block_number, block_hash)),
        block_info,
        ChainInfo::default(),
        VersionedConstants::default(),
        BouncerConfig::create_for_testing(),
        false,
    )
    .unwrap();

    let written_hash = state.get_storage_at(
        ContractAddress::from(constants::BLOCK_HASH_CONTRACT_ADDRESS),
        StorageKey::from(block_number),
    );
    assert_eq!(written_hash.unwrap(), block_hash);

    // Test that block pre-process with block hash None is successful only within the allowed
    // block number interval.
    let mut block_info = BlockInfo::create_for_testing();
    block_info.block_number = BlockNumber(constants::STORED_BLOCK_HASH_BUFFER - 1);
    assert!(
        pre_process_block(
            &mut state,
            None,
            block_info,
            ChainInfo::default(),
            VersionedConstants::default(),
            BouncerConfig::create_for_testing(),
            false,
        )
        .is_ok()
    );

    let mut block_info = BlockInfo::create_for_testing();
    block_info.block_number = BlockNumber(constants::STORED_BLOCK_HASH_BUFFER);
    let error = pre_process_block(
        &mut state,
        None,
        block_info,
        ChainInfo::default(),
        VersionedConstants::default(),
        BouncerConfig::create_for_testing(),
        false,
    );
    assert_eq!(
        format!(
            "A block hash must be provided for block number > {}.",
            constants::STORED_BLOCK_HASH_BUFFER
        ),
        format!("{}", error.unwrap_err())
    );
}
