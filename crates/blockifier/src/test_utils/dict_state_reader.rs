use std::collections::HashMap;

use starknet_api::core::{
    calculate_contract_address, ClassHash, CompiledClassHash, ContractAddress, Nonce, PatriciaKey,
};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Calldata, ContractAddressSalt};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};

use crate::abi::abi_utils::get_storage_var_address;
use crate::execution::contract_class::{ContractClass, ContractClassV0, ContractClassV1};
use crate::state::cached_state::{CachedState, ContractClassMapping, ContractStorageKey};
use crate::state::errors::StateError;
use crate::state::state_api::{StateReader, StateResult};
use crate::test_utils::{
    LEGACY_TEST_CLASS_HASH, LEGACY_TEST_CONTRACT_ADDRESS, LEGACY_TEST_CONTRACT_CAIRO1_PATH,
    RESERVE_0, RESERVE_1, SECURITY_TEST_CLASS_HASH, SECURITY_TEST_CONTRACT_ADDRESS,
    SECURITY_TEST_CONTRACT_CAIRO0_PATH, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS,
    TEST_CONTRACT_ADDRESS_2, TEST_CONTRACT_CAIRO0_PATH, TEST_CONTRACT_CAIRO1_PATH,
    TEST_EMPTY_CONTRACT_CAIRO0_PATH, TEST_EMPTY_CONTRACT_CAIRO1_PATH,
    TEST_EMPTY_CONTRACT_CLASS_HASH, TEST_PAIR_SKELETON_CONTRACT_ADDRESS1,
    TEST_PAIR_SKELETON_CONTRACT_CLASS_HASH, TEST_PAIR_SKELETON_CONTRACT_PATH,
};

/// A simple implementation of `StateReader` using `HashMap`s as storage.
#[derive(Debug, Default)]
pub struct DictStateReader {
    pub storage_view: HashMap<ContractStorageKey, StarkFelt>,
    pub address_to_nonce: HashMap<ContractAddress, Nonce>,
    pub address_to_class_hash: HashMap<ContractAddress, ClassHash>,
    pub class_hash_to_class: HashMap<ClassHash, ContractClass>,
    pub class_hash_to_compiled_class_hash: HashMap<ClassHash, CompiledClassHash>,
}

impl StateReader for DictStateReader {
    fn get_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        let contract_storage_key = (contract_address, key);
        let value = self.storage_view.get(&contract_storage_key).copied().unwrap_or_default();
        Ok(value)
    }

    fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce> {
        let nonce = self.address_to_nonce.get(&contract_address).copied().unwrap_or_default();
        Ok(nonce)
    }

    fn get_compiled_contract_class(
        &mut self,
        class_hash: &ClassHash,
    ) -> StateResult<ContractClass> {
        let contract_class = self.class_hash_to_class.get(class_hash).cloned();
        match contract_class {
            Some(contract_class) => Ok(contract_class),
            _ => Err(StateError::UndeclaredClassHash(*class_hash)),
        }
    }

    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        let class_hash =
            self.address_to_class_hash.get(&contract_address).copied().unwrap_or_default();
        Ok(class_hash)
    }

    fn get_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
    ) -> StateResult<starknet_api::core::CompiledClassHash> {
        let compiled_class_hash =
            self.class_hash_to_compiled_class_hash.get(&class_hash).copied().unwrap_or_default();
        Ok(compiled_class_hash)
    }
}

pub fn deprecated_create_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = get_class_hash_to_v0_class_mapping();
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
    let class_hash_to_class = get_class_hash_to_v1_class_mapping();

    let mut address_to_class_hash = common_map_setup();
    address_to_class_hash.insert(
        contract_address!(LEGACY_TEST_CONTRACT_ADDRESS),
        class_hash!(LEGACY_TEST_CLASS_HASH),
    );

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

pub fn create_deploy_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = get_class_hash_to_v1_class_mapping();
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
        (
            contract_address!(TEST_PAIR_SKELETON_CONTRACT_ADDRESS1),
            class_hash!(TEST_PAIR_SKELETON_CONTRACT_CLASS_HASH),
        ),
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
        (
            class_hash!(TEST_PAIR_SKELETON_CONTRACT_CLASS_HASH),
            ContractClassV0::from_file(TEST_PAIR_SKELETON_CONTRACT_PATH).into(),
        ),
    ])
}

fn get_class_hash_to_v1_class_mapping() -> ContractClassMapping {
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

fn get_address_to_v0_class_hash() -> HashMap<ContractAddress, ClassHash> {
    let mut address_to_class_hash = common_map_setup();
    address_to_class_hash.insert(
        contract_address!(SECURITY_TEST_CONTRACT_ADDRESS),
        class_hash!(SECURITY_TEST_CLASS_HASH),
    );
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
