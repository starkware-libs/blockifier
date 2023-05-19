use std::collections::HashMap;

use assert_matches::assert_matches;
use indexmap::indexmap;
use pretty_assertions::assert_eq;
use starknet_api::core::PatriciaKey;
use starknet_api::hash::StarkHash;
use starknet_api::{patricia_key, stark_felt};

use super::*;
use crate::test_utils::{
    deprecated_create_test_state, get_test_contract_class, DictStateReader, TEST_CLASS_HASH,
    TEST_EMPTY_CONTRACT_CLASS_HASH,
};

fn set_initial_state_values(
    state: &mut CachedState<DictStateReader>,
    class_hash_to_class: ContractClassMapping,
    nonce_initial_values: HashMap<ContractAddress, Nonce>,
    class_hash_initial_values: HashMap<ContractAddress, ClassHash>,
    storage_initial_values: HashMap<ContractStorageKey, StarkFelt>,
) {
    assert!(state.cache == StateCache::default(), "Cache already initialized.");

    state.class_hash_to_class = class_hash_to_class;
    state.cache.class_hash_initial_values.extend(class_hash_initial_values);
    state.cache.nonce_initial_values.extend(nonce_initial_values);
    state.cache.storage_initial_values.extend(storage_initial_values);
}

#[test]
fn get_uninitialized_storage_value() {
    let mut state: CachedState<DictStateReader> = CachedState::default();
    let contract_address = ContractAddress(patricia_key!("0x1"));
    let key = StorageKey(patricia_key!("0x10"));

    assert_eq!(state.get_storage_at(contract_address, key).unwrap(), StarkFelt::default());
}

#[test]
fn get_and_set_storage_value() {
    let contract_address0 = ContractAddress(patricia_key!("0x100"));
    let contract_address1 = ContractAddress(patricia_key!("0x200"));
    let key0 = StorageKey(patricia_key!("0x10"));
    let key1 = StorageKey(patricia_key!("0x20"));
    let storage_val0: StarkFelt = stark_felt!("0x1");
    let storage_val1: StarkFelt = stark_felt!("0x5");

    let mut state = CachedState::new(DictStateReader {
        storage_view: HashMap::from([
            ((contract_address0, key0), storage_val0),
            ((contract_address1, key1), storage_val1),
        ]),
        ..Default::default()
    });
    assert_eq!(state.get_storage_at(contract_address0, key0).unwrap(), storage_val0);
    assert_eq!(state.get_storage_at(contract_address1, key1).unwrap(), storage_val1);

    let modified_storage_value0 = stark_felt!("0xA");
    state.set_storage_at(contract_address0, key0, modified_storage_value0);
    assert_eq!(state.get_storage_at(contract_address0, key0).unwrap(), modified_storage_value0);
    assert_eq!(state.get_storage_at(contract_address1, key1).unwrap(), storage_val1);

    let modified_storage_value1 = stark_felt!("0x7");
    state.set_storage_at(contract_address1, key1, modified_storage_value1);
    assert_eq!(state.get_storage_at(contract_address0, key0).unwrap(), modified_storage_value0);
    assert_eq!(state.get_storage_at(contract_address1, key1).unwrap(), modified_storage_value1);
}

#[test]
fn cast_between_storage_mapping_types() {
    let empty_map: IndexMap<ContractAddress, IndexMap<StorageKey, StarkFelt>> = IndexMap::default();
    assert_eq!(empty_map, IndexMap::from(StorageView::default()));

    let contract_address0 = ContractAddress(patricia_key!("0x100"));
    let contract_address1 = ContractAddress(patricia_key!("0x200"));
    let key0 = StorageKey(patricia_key!("0x10"));
    let key1 = StorageKey(patricia_key!("0x20"));
    let storage_val0: StarkFelt = stark_felt!("0x1");
    let storage_val1: StarkFelt = stark_felt!("0x5");
    let storage_val2: StarkFelt = stark_felt!("0xa");

    let storage_map = StorageView(HashMap::from([
        ((contract_address0, key0), storage_val0),
        ((contract_address0, key1), storage_val1),
        ((contract_address1, key0), storage_val2),
    ]));

    let expected_indexed_map = IndexMap::from([
        (contract_address0, indexmap!(key0 => storage_val0, key1 => storage_val1)),
        (contract_address1, indexmap!(key0 => storage_val2)),
    ]);
    assert_eq!(expected_indexed_map, IndexMap::from(storage_map));
}

#[test]
fn get_uninitialized_value() {
    let mut state = CachedState::new(DictStateReader::default());
    let contract_address = ContractAddress(patricia_key!("0x1"));

    assert_eq!(state.get_nonce_at(contract_address).unwrap(), Nonce::default());
}

#[test]
fn get_and_increment_nonce() {
    let contract_address1 = ContractAddress(patricia_key!("0x100"));
    let contract_address2 = ContractAddress(patricia_key!("0x200"));
    let initial_nonce = Nonce(stark_felt!("0x1"));

    let mut state = CachedState::new(DictStateReader {
        address_to_nonce: HashMap::from([
            (contract_address1, initial_nonce),
            (contract_address2, initial_nonce),
        ]),
        ..Default::default()
    });
    assert_eq!(state.get_nonce_at(contract_address1).unwrap(), initial_nonce);
    assert_eq!(state.get_nonce_at(contract_address2).unwrap(), initial_nonce);

    assert!(state.increment_nonce(contract_address1).is_ok());
    let nonce1_plus_one = Nonce(stark_felt!("0x2"));
    assert_eq!(state.get_nonce_at(contract_address1).unwrap(), nonce1_plus_one);
    assert_eq!(state.get_nonce_at(contract_address2).unwrap(), initial_nonce);

    assert!(state.increment_nonce(contract_address1).is_ok());
    let nonce1_plus_two = Nonce(stark_felt!("0x3"));
    assert_eq!(state.get_nonce_at(contract_address1).unwrap(), nonce1_plus_two);
    assert_eq!(state.get_nonce_at(contract_address2).unwrap(), initial_nonce);

    assert!(state.increment_nonce(contract_address2).is_ok());
    let nonce2_plus_one = Nonce(stark_felt!("0x2"));
    assert_eq!(state.get_nonce_at(contract_address1).unwrap(), nonce1_plus_two);
    assert_eq!(state.get_nonce_at(contract_address2).unwrap(), nonce2_plus_one);
}

#[test]
fn get_contract_class() {
    // Positive flow.
    let existing_class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    let mut state = deprecated_create_test_state();
    assert_eq!(
        state.get_compiled_contract_class(&existing_class_hash).unwrap(),
        get_test_contract_class()
    );

    // Negative flow.
    let missing_class_hash = ClassHash(stark_felt!("0x101"));
    assert_matches!(
        state.get_compiled_contract_class(&missing_class_hash).unwrap_err(),
        StateError::UndeclaredClassHash(undeclared) if undeclared == missing_class_hash
    );
}

#[test]
fn get_uninitialized_class_hash_value() {
    let mut state = CachedState::new(DictStateReader::default());
    let valid_contract_address = ContractAddress(patricia_key!("0x1"));

    assert_eq!(state.get_class_hash_at(valid_contract_address).unwrap(), ClassHash::default());
}

#[test]
fn set_and_get_contract_hash() {
    let contract_address = ContractAddress(patricia_key!("0x1"));
    let mut state = CachedState::new(DictStateReader::default());
    let class_hash = ClassHash(stark_felt!("0x10"));

    assert!(state.set_class_hash_at(contract_address, class_hash).is_ok());
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), class_hash);
}

#[test]
fn cannot_set_class_hash_to_uninitialized_contract() {
    let mut state = CachedState::new(DictStateReader::default());

    let uninitialized_contract_address = ContractAddress::default();
    let class_hash = ClassHash(stark_felt!("0x100"));
    assert_matches!(
        state.set_class_hash_at(uninitialized_contract_address, class_hash).unwrap_err(),
        StateError::OutOfRangeContractAddress
    );
}

#[test]
fn cached_state_state_diff_conversion() {
    // This will not appear in the diff, since this mapping is immutable for the current version we
    // are aligned with.
    let test_class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    let class_hash_to_class = HashMap::from([(test_class_hash, get_test_contract_class())]);

    let nonce_initial_values = HashMap::new();

    // contract_address0 will correspond to keys that are not touched in the test.
    // contract_address1 to keys whose value is overwritten with the same value it previously had
    // (so should not appear in the diff).
    // contract_address2 to keys whose value changes to a different value (so should appear in the
    // diff).
    let contract_address0 = ContractAddress(patricia_key!("0x100"));
    let contract_address1 = ContractAddress(patricia_key!("0x200"));
    let contract_address2 = ContractAddress(patricia_key!("0x300"));

    // key_x will not be changed.
    // key_y will be changed, but only with contract_address2 the value ends up being different, so
    // should only appear with contract_address2.
    let key_x = StorageKey(patricia_key!("0x10"));
    let key_y = StorageKey(patricia_key!("0x20"));
    let storage_val0: StarkFelt = stark_felt!("0x1");
    let storage_val1: StarkFelt = stark_felt!("0x5");
    let storage_val2: StarkFelt = stark_felt!("0x6");
    let storage_initial_values = HashMap::from([
        ((contract_address0, key_x), storage_val0),
        ((contract_address1, key_y), storage_val1),
        ((contract_address2, key_x), storage_val2),
        ((contract_address2, key_y), storage_val2),
    ]);

    let address_to_class_hash_initial_values =
        HashMap::from([(contract_address0, test_class_hash)]);

    let mut state = CachedState::default();

    // Populate the initial value in the state cache (the init above is only for the StateReader).
    set_initial_state_values(
        &mut state,
        class_hash_to_class,
        nonce_initial_values,
        address_to_class_hash_initial_values,
        storage_initial_values,
    );

    // Declare a new class.
    let class_hash = ClassHash(stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH));
    let compiled_class_hash = CompiledClassHash(stark_felt!(1_u8));
    state.set_compiled_class_hash(class_hash, compiled_class_hash).unwrap();

    // Write the initial value using key contract_address1.
    state.set_storage_at(contract_address1, key_y, storage_val1);

    // Write new values using key contract_address2.
    let new_value = stark_felt!("0x12345678");
    state.set_storage_at(contract_address2, key_y, new_value);
    assert!(state.increment_nonce(contract_address2).is_ok());
    let new_class_hash = ClassHash(stark_felt!("0x11111111"));
    assert!(state.set_class_hash_at(contract_address2, new_class_hash).is_ok());

    // Only changes to contract_address2 should be shown, since contract_address_0 wasn't changed
    // and contract_address_1 was changed but ended up with the original values.
    let expected_state_diff = CommitmentStateDiff {
        address_to_class_hash: IndexMap::from_iter([(contract_address2, new_class_hash)]),
        storage_updates: IndexMap::from_iter([(contract_address2, indexmap! {key_y => new_value})]),
        class_hash_to_compiled_class_hash: IndexMap::from_iter([(class_hash, compiled_class_hash)]),
        address_to_nonce: IndexMap::from_iter([(contract_address2, Nonce(StarkFelt::from(1_u64)))]),
    };

    assert_eq!(expected_state_diff, state.to_state_diff());
}

#[test]
fn count_actual_state_changes() {
    let contract_address = ContractAddress(patricia_key!("0x100"));
    let class_hash = ClassHash(stark_felt!("0x10"));
    let key = StorageKey(patricia_key!("0x10"));
    let storage_val: StarkFelt = stark_felt!("0x1");

    let mut state = CachedState::new(DictStateReader::default());
    state.set_class_hash_at(contract_address, class_hash).unwrap();
    state.set_storage_at(contract_address, key, storage_val);

    let (n_storage_updates, n_modified_contracts, n_class_updates) =
        state.count_actual_state_changes();

    assert_eq!((n_storage_updates, n_modified_contracts, n_class_updates), (1, 1, 1));
}
