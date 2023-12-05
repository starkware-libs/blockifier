use std::collections::HashMap;

use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Calldata, ContractAddressSalt};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};
use strum::IntoEnumIterator;

use super::contracts::FeatureContract;
use super::CairoVersion;
use crate::abi::abi_utils::get_storage_var_address;
use crate::execution::contract_class::ContractClassV0;
use crate::state::cached_state::{CachedState, ContractClassMapping};
use crate::test_utils::contracts::FeatureContractId;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::{
    RESERVE_0, RESERVE_1, TEST_PAIR_SKELETON_CONTRACT_ADDRESS1,
    TEST_PAIR_SKELETON_CONTRACT_CLASS_HASH, TEST_PAIR_SKELETON_CONTRACT_PATH,
};

pub fn deprecated_create_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = get_class_hash_to_class_mapping();
    let address_to_class_hash = get_address_to_v0_class_hash();
    let storage_view = get_storage_values_for_deprecated_test_state();

    CachedState::from(DictStateReader {
        class_hash_to_class,
        address_to_class_hash,
        storage_view,
        ..Default::default()
    })
}

pub fn create_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = get_class_hash_to_class_mapping();

    let mut address_to_class_hash = common_map_setup();
    let legacy_contract =
        FeatureContract::new(FeatureContractId::LegacyTestContract, CairoVersion::Cairo0, 0);
    address_to_class_hash.insert(legacy_contract.address, legacy_contract.class_hash);

    CachedState::from(DictStateReader {
        class_hash_to_class,
        address_to_class_hash,
        ..Default::default()
    })
}

pub fn deprecated_create_deploy_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = get_class_hash_to_class_mapping();
    create_deploy_test_state_from_classes(class_hash_to_class)
}

pub fn create_deploy_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = get_class_hash_to_class_mapping();
    create_deploy_test_state_from_classes(class_hash_to_class)
}

fn create_deploy_test_state_from_classes(
    class_hash_to_class: ContractClassMapping,
) -> CachedState<DictStateReader> {
    let class_hash = FeatureContractId::TestContract.get_class_hash(CairoVersion::Cairo0);
    let contract_address = FeatureContractId::TestContract.get_address(CairoVersion::Cairo0, 0);
    let another_contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &calldata![
            stark_felt!(3_u8), // Calldata: address.
            stark_felt!(3_u8)  // Calldata: value.
        ],
        FeatureContractId::TestContract.get_address(CairoVersion::Cairo0, 0),
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
    let test_contract_cairo0 =
        FeatureContract::new(FeatureContractId::TestContract, CairoVersion::Cairo0, 0);
    let other_test_contract_cairo0 =
        FeatureContract::new(FeatureContractId::TestContract, CairoVersion::Cairo0, 1);
    let test_contract_cairo1 =
        FeatureContract::new(FeatureContractId::TestContract, CairoVersion::Cairo1, 0);
    let other_test_contract_cairo1 =
        FeatureContract::new(FeatureContractId::TestContract, CairoVersion::Cairo1, 1);
    HashMap::from([
        (test_contract_cairo0.address, test_contract_cairo0.class_hash),
        (other_test_contract_cairo0.address, other_test_contract_cairo0.class_hash),
        (test_contract_cairo1.address, test_contract_cairo1.class_hash),
        (other_test_contract_cairo1.address, other_test_contract_cairo1.class_hash),
        (
            contract_address!(TEST_PAIR_SKELETON_CONTRACT_ADDRESS1),
            class_hash!(TEST_PAIR_SKELETON_CONTRACT_CLASS_HASH),
        ),
    ])
}

fn get_class_hash_to_class_mapping() -> ContractClassMapping {
    let mut mapping = HashMap::new();
    for cairo_version in CairoVersion::iter() {
        for feature_contract_id in FeatureContractId::iter() {
            // TODO(Dori, 1/1/2024): Add implementations to all contracts in each Cairo version.
            match (cairo_version, feature_contract_id) {
                (CairoVersion::Cairo0, FeatureContractId::LegacyTestContract)
                | (CairoVersion::Cairo1, FeatureContractId::SecurityTests) => continue,
                _ => {
                    let feature_contract =
                        FeatureContract::new(feature_contract_id, cairo_version, 0);
                    mapping.insert(feature_contract.class_hash, feature_contract.get_class());
                }
            }
        }
    }
    mapping.insert(
        class_hash!(TEST_PAIR_SKELETON_CONTRACT_CLASS_HASH),
        ContractClassV0::from_file(TEST_PAIR_SKELETON_CONTRACT_PATH).into(),
    );
    mapping
}

fn get_address_to_v0_class_hash() -> HashMap<ContractAddress, ClassHash> {
    let mut address_to_class_hash = common_map_setup();
    let security_test_contract =
        FeatureContract::new(FeatureContractId::SecurityTests, CairoVersion::Cairo0, 0);
    address_to_class_hash.insert(security_test_contract.address, security_test_contract.class_hash);
    address_to_class_hash
}

fn get_storage_values_for_deprecated_test_state()
-> HashMap<(ContractAddress, StorageKey), StarkFelt> {
    let pair_address = contract_address!(TEST_PAIR_SKELETON_CONTRACT_ADDRESS1);
    let reserve0_address = get_storage_var_address("_reserve0", &[]);
    let reserve1_address = get_storage_var_address("_reserve1", &[]);
    // Override the pair's reserves data, since the constructor is not called.
    HashMap::from([
        ((pair_address, reserve0_address), stark_felt!(RESERVE_0)),
        ((pair_address, reserve1_address), stark_felt!(RESERVE_1)),
    ])
}
