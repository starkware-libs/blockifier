use std::collections::HashMap;

use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{Calldata, ContractAddressSalt};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};

use crate::execution::contract_class::{ContractClassV0, ContractClassV1, SierraContractClassV1};
use crate::state::cached_state::{CachedState, ContractClassMapping};
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::{
    ERC20_FULL_CONTRACT_PATH, LEGACY_TEST_CLASS_HASH, LEGACY_TEST_CONTRACT_CAIRO1_PATH,
    SECURITY_TEST_CLASS_HASH, SECURITY_TEST_CONTRACT_ADDRESS, SECURITY_TEST_CONTRACT_CAIRO0_PATH,
    TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS, TEST_CONTRACT_ADDRESS_2, TEST_CONTRACT_CAIRO0_PATH,
    TEST_CONTRACT_CAIRO1_PATH, TEST_CONTRACT_SIERRA_PATH, TEST_EMPTY_CONTRACT_CAIRO0_PATH,
    TEST_EMPTY_CONTRACT_CAIRO1_PATH, TEST_EMPTY_CONTRACT_CLASS_HASH,
    TEST_ERC20_FULL_CONTRACT_CLASS_HASH,
};

pub fn deprecated_create_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = get_class_hash_to_v0_class_mapping();
    let address_to_class_hash = get_address_to_v0_class_hash();

    CachedState::from(DictStateReader {
        class_hash_to_class,
        address_to_class_hash,
        ..Default::default()
    })
}

pub fn deprecated_create_deploy_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = get_class_hash_to_v0_class_mapping();
    create_deploy_test_state_from_classes(class_hash_to_class)
}
pub fn create_deploy_test_state(contract_type: FeatureContract) -> CachedState<DictStateReader> {
    let class_hash_to_class = get_class_hash_to_v1_class_mapping(contract_type);
    create_deploy_test_state_from_classes(class_hash_to_class)
}

pub fn create_deploy_test_state_vm() -> CachedState<DictStateReader> {
    let class_hash_to_class = get_class_hash_to_v1_class_mapping_vm();
    create_deploy_test_state_from_classes(class_hash_to_class)
}

fn create_deploy_test_state_from_classes(
    class_hash_to_class: ContractClassMapping,
) -> CachedState<DictStateReader> {
    let class_hash = class_hash!(TEST_CLASS_HASH);
    let contract_address = contract_address!(TEST_CONTRACT_ADDRESS);
    let another_contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &calldata![
            stark_felt!(3_u8), // Calldata: address.
            stark_felt!(3_u8)  // Calldata: value.
        ],
        contract_address!(TEST_CONTRACT_ADDRESS),
    )
    .unwrap();
    let address_to_class_hash =
        HashMap::from([(contract_address, class_hash), (another_contract_address, class_hash)]);

    CachedState::from(DictStateReader {
        class_hash_to_class,
        address_to_class_hash,
        ..Default::default()
    })
}

fn common_map_setup() -> HashMap<ContractAddress, ClassHash> {
    HashMap::from([
        (contract_address!(TEST_CONTRACT_ADDRESS), class_hash!(TEST_CLASS_HASH)),
        (contract_address!(TEST_CONTRACT_ADDRESS_2), class_hash!(TEST_CLASS_HASH)),
    ])
}

fn get_class_hash_to_v0_class_mapping() -> ContractClassMapping {
    HashMap::from([
        (
            class_hash!(TEST_CLASS_HASH),
            ContractClassV0::from_file(TEST_CONTRACT_CAIRO0_PATH).into(),
        ),
        (
            class_hash!(SECURITY_TEST_CLASS_HASH),
            ContractClassV0::from_file(SECURITY_TEST_CONTRACT_CAIRO0_PATH).into(),
        ),
        (
            class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
            ContractClassV0::from_file(TEST_EMPTY_CONTRACT_CAIRO0_PATH).into(),
        ),
    ])
}

fn get_class_hash_to_v1_class_mapping(contract_type: FeatureContract) -> ContractClassMapping {
    HashMap::from([
        match contract_type {
            FeatureContract::TestContract(_) => (
                class_hash!(TEST_CLASS_HASH),
                ContractClassV1::from_file(TEST_CONTRACT_CAIRO1_PATH).into(),
            ),
            FeatureContract::SierraTestContract => (
                class_hash!(TEST_CLASS_HASH),
                SierraContractClassV1::from_file(TEST_CONTRACT_SIERRA_PATH).into(),
            ),
            _ => panic!("Unsupported contract type"),
        },
        (
            class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
            ContractClassV1::from_file(TEST_EMPTY_CONTRACT_CAIRO1_PATH).into(),
        ),
        (
            class_hash!(LEGACY_TEST_CLASS_HASH),
            ContractClassV1::from_file(LEGACY_TEST_CONTRACT_CAIRO1_PATH).into(),
        ),
    ])
}

fn get_class_hash_to_v1_class_mapping_vm() -> ContractClassMapping {
    HashMap::from([
        (
            class_hash!(TEST_CLASS_HASH),
            ContractClassV1::from_file(TEST_CONTRACT_CAIRO1_PATH).into(),
        ),
        (
            class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
            ContractClassV1::from_file(TEST_EMPTY_CONTRACT_CAIRO1_PATH).into(),
        ),
        (
            class_hash!(LEGACY_TEST_CLASS_HASH),
            ContractClassV1::from_file(LEGACY_TEST_CONTRACT_CAIRO1_PATH).into(),
        ),
    ])
}

pub fn get_erc20_class_hash_mapping() -> ContractClassMapping {
    HashMap::from([
        (
            class_hash!(TEST_ERC20_FULL_CONTRACT_CLASS_HASH),
            SierraContractClassV1::from_file(ERC20_FULL_CONTRACT_PATH).into(),
        ),
        (
            class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
            ContractClassV1::from_file(TEST_EMPTY_CONTRACT_CAIRO1_PATH).into(),
        ),
    ])
}

fn get_address_to_v0_class_hash() -> HashMap<ContractAddress, ClassHash> {
    let mut address_to_class_hash = common_map_setup();
    address_to_class_hash.insert(
        contract_address!(SECURITY_TEST_CONTRACT_ADDRESS),
        class_hash!(SECURITY_TEST_CLASS_HASH),
    );
    address_to_class_hash
}
