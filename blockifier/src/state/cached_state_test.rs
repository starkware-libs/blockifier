use std::collections::HashMap;

use assert_matches::assert_matches;
use indexmap::indexmap;
use pretty_assertions::assert_eq;
use starknet_api::core::PatriciaKey;
use starknet_api::hash::StarkHash;
use starknet_api::{patky, shash};

use super::*;
use crate::state::errors::StateReaderError;
use crate::test_utils::{create_test_state, get_test_contract_class, TEST_CLASS_HASH};

#[test]
fn get_uninitialized_storage_value() {
    let mut state: CachedState<DictStateReader> = CachedState::default();
    let contract_address = ContractAddress(patky!("0x1"));
    let key = StorageKey(patky!("0x10"));

    assert_eq!(*state.get_storage_at(contract_address, key).unwrap(), StarkFelt::default());
}

#[test]
fn get_and_set_storage_value() {
    let contract_address0 = ContractAddress(patky!("0x100"));
    let contract_address1 = ContractAddress(patky!("0x200"));
    let key0 = StorageKey(patky!("0x10"));
    let key1 = StorageKey(patky!("0x20"));
    let storage_val0: StarkFelt = shash!("0x1");
    let storage_val1: StarkFelt = shash!("0x5");

    let mut state = CachedState::new(DictStateReader {
        storage_view: HashMap::from([
            ((contract_address0, key0), storage_val0),
            ((contract_address1, key1), storage_val1),
        ]),
        ..Default::default()
    });
    assert_eq!(*state.get_storage_at(contract_address0, key0).unwrap(), storage_val0);
    assert_eq!(*state.get_storage_at(contract_address1, key1).unwrap(), storage_val1);

    let modified_storage_value0 = shash!("0xA");
    state.set_storage_at(contract_address0, key0, modified_storage_value0);
    assert_eq!(*state.get_storage_at(contract_address0, key0).unwrap(), modified_storage_value0);
    assert_eq!(*state.get_storage_at(contract_address1, key1).unwrap(), storage_val1);

    let modified_storage_value1 = shash!("0x7");
    state.set_storage_at(contract_address1, key1, modified_storage_value1);
    assert_eq!(*state.get_storage_at(contract_address0, key0).unwrap(), modified_storage_value0);
    assert_eq!(*state.get_storage_at(contract_address1, key1).unwrap(), modified_storage_value1);
}

#[test]
fn cast_between_storage_mapping_types() {
    let empty_map: IndexMap<ContractAddress, IndexMap<StorageKey, StarkFelt>> = IndexMap::default();
    assert_eq!(empty_map, StorageView::default().into());

    let contract_address0 = ContractAddress(patky!("0x100"));
    let contract_address1 = ContractAddress(patky!("0x200"));
    let key0 = StorageKey(patky!("0x10"));
    let key1 = StorageKey(patky!("0x20"));
    let storage_val0: StarkFelt = shash!("0x1");
    let storage_val1: StarkFelt = shash!("0x5");
    let storage_val2: StarkFelt = shash!("0xa");

    let storage_map = StorageView(HashMap::from([
        ((contract_address0, key0), storage_val0),
        ((contract_address0, key1), storage_val1),
        ((contract_address1, key0), storage_val2),
    ]));

    let expected_indexed_map = IndexMap::from([
        (contract_address0, indexmap!(key0 => storage_val0, key1 => storage_val1)),
        (contract_address1, indexmap!(key0 => storage_val2)),
    ]);
    assert_eq!(expected_indexed_map, storage_map.into());
}

#[test]
fn get_uninitialized_value() {
    let mut state = CachedState::new(DictStateReader::default());
    let contract_address = ContractAddress(patky!("0x1"));

    assert_eq!(*state.get_nonce_at(contract_address).unwrap(), Nonce::default());
}

#[test]
fn get_and_increment_nonce() {
    let contract_address1 = ContractAddress(patky!("0x100"));
    let contract_address2 = ContractAddress(patky!("0x200"));
    let initial_nonce = Nonce(shash!("0x1"));

    let mut state = CachedState::new(DictStateReader {
        address_to_nonce: HashMap::from([
            (contract_address1, initial_nonce),
            (contract_address2, initial_nonce),
        ]),
        ..Default::default()
    });
    assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), initial_nonce);
    assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), initial_nonce);

    assert!(state.increment_nonce(contract_address1).is_ok());
    let nonce1_plus_one = Nonce(shash!("0x2"));
    assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), nonce1_plus_one);
    assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), initial_nonce);

    assert!(state.increment_nonce(contract_address1).is_ok());
    let nonce1_plus_two = Nonce(shash!("0x3"));
    assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), nonce1_plus_two);
    assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), initial_nonce);

    assert!(state.increment_nonce(contract_address2).is_ok());
    let nonce2_plus_one = Nonce(shash!("0x2"));
    assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), nonce1_plus_two);
    assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), nonce2_plus_one);
}

#[test]
fn get_contract_class() {
    // Positive flow.
    let existing_class_hash = ClassHash(shash!(TEST_CLASS_HASH));
    let mut state = create_test_state();
    assert_eq!(*state.get_contract_class(&existing_class_hash).unwrap(), get_test_contract_class());

    // Negative flow.
    let missing_class_hash = ClassHash(shash!("0x101"));
    assert_matches!(
        state.get_contract_class(&missing_class_hash).unwrap_err(),
        StateError::StateReaderError(
            StateReaderError::UndeclaredClassHash(undeclared)
        ) if undeclared == missing_class_hash
    );
}

#[test]
fn get_uninitialized_class_hash_value() {
    let mut state = CachedState::new(DictStateReader::default());
    let valid_contract_address = ContractAddress(patky!("0x1"));

    assert_eq!(*state.get_class_hash_at(valid_contract_address).unwrap(), ClassHash::default());
}

#[test]
fn set_and_get_contract_hash() {
    let contract_address = ContractAddress(patky!("0x1"));
    let mut state = CachedState::new(DictStateReader::default());
    let class_hash = ClassHash(shash!("0x10"));

    assert!(state.set_class_hash_at(contract_address, class_hash).is_ok());
    assert_eq!(*state.get_class_hash_at(contract_address).unwrap(), class_hash);
}

#[test]
fn cannot_set_class_hash_to_deployed_address() {
    let contract_address = ContractAddress(patky!("0x1"));
    let deployed_class_hash = ClassHash(shash!("0x10"));
    let mut state = CachedState::new(DictStateReader {
        address_to_class_hash: HashMap::from([(contract_address, deployed_class_hash)]),
        ..Default::default()
    });

    let new_class_hash = ClassHash(shash!("0x100"));
    assert_matches!(
        state.set_class_hash_at(contract_address, new_class_hash).unwrap_err(),
        StateError::UnavailableContractAddress(..)
    );
}

#[test]
fn cannot_set_class_hash_to_uninitialized_contract() {
    let mut state = CachedState::new(DictStateReader::default());

    let uninitialized_contract_address = ContractAddress::default();
    let class_hash = ClassHash(shash!("0x100"));
    assert_matches!(
        state.set_class_hash_at(uninitialized_contract_address, class_hash).unwrap_err(),
        StateError::OutOfRangeContractAddress
    );
}
