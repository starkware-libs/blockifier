use std::collections::HashMap;

use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{Calldata, ContractAddressSalt};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};

use super::CairoVersion;
use crate::execution::contract_class::{ContractClass, ContractClassV0};
use crate::state::cached_state::{CachedState, ContractClassMapping};
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::{
    SECURITY_TEST_CLASS_HASH, SECURITY_TEST_CONTRACT_ADDRESS, SECURITY_TEST_CONTRACT_CAIRO0_PATH,
    TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS, TEST_CONTRACT_ADDRESS_2, TEST_CONTRACT_CAIRO0_PATH,
    TEST_EMPTY_CONTRACT_CAIRO0_PATH, TEST_EMPTY_CONTRACT_CLASS_HASH,
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

pub fn create_contracts_mappings(
    contract_instances: &[(FeatureContract, u8)],
) -> (HashMap<ClassHash, ContractClass>, HashMap<ContractAddress, ClassHash>) {
    let mut class_hash_to_class = HashMap::new();
    let mut address_to_class_hash = HashMap::new();
    for (contract, n_instances) in contract_instances.iter() {
        let class_hash = contract.get_class_hash();
        class_hash_to_class.insert(class_hash, contract.get_class());
        for instance in 0..*n_instances {
            let instance_address = contract.get_instance_address(instance);
            address_to_class_hash.insert(instance_address, class_hash);
        }
    }
    (class_hash_to_class, address_to_class_hash)
}

pub fn create_deploy_test_state(cairo_version: CairoVersion) -> CachedState<DictStateReader> {
    let test_contract = FeatureContract::TestContract(cairo_version);
    let (class_hash_to_class, mut address_to_class_hash) = create_contracts_mappings(&[
        (test_contract, 1),
        (FeatureContract::Empty(cairo_version), 1),
        (FeatureContract::LegacyTestContract, 1),
    ]);
    let class_hash = test_contract.get_class_hash();
    let another_contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &calldata![
            stark_felt!(3_u8), // Calldata: address.
            stark_felt!(3_u8)  // Calldata: value.
        ],
        test_contract.get_instance_address(0),
    )
    .unwrap();
    address_to_class_hash.insert(another_contract_address, class_hash);

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

fn get_address_to_v0_class_hash() -> HashMap<ContractAddress, ClassHash> {
    let mut address_to_class_hash = common_map_setup();
    address_to_class_hash.insert(
        contract_address!(SECURITY_TEST_CONTRACT_ADDRESS),
        class_hash!(SECURITY_TEST_CLASS_HASH),
    );
    address_to_class_hash
}
