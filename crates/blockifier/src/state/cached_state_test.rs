use std::collections::HashMap;

use assert_matches::assert_matches;
use indexmap::indexmap;
use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::core::PatriciaKey;
use starknet_api::{class_hash, contract_address, felt, patricia_key};

use crate::context::{BlockContext, ChainInfo};
use crate::state::cached_state::*;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::CairoVersion;
use crate::{compiled_class_hash, nonce, storage_key};
const CONTRACT_ADDRESS: &str = "0x100";

fn set_initial_state_values(
    state: &mut CachedState<DictStateReader>,
    class_hash_to_class: ContractClassMapping,
    nonce_initial_values: HashMap<ContractAddress, Nonce>,
    class_hash_initial_values: HashMap<ContractAddress, ClassHash>,
    storage_initial_values: HashMap<StorageEntry, Felt>,
) {
    assert!(*state.cache.borrow() == StateCache::default(), "Cache already initialized.");

    state.class_hash_to_class.replace(class_hash_to_class);
    state.cache.get_mut().initial_reads.class_hashes.extend(class_hash_initial_values);
    state.cache.get_mut().initial_reads.nonces.extend(nonce_initial_values);
    state.cache.get_mut().initial_reads.storage.extend(storage_initial_values);
}

#[test]
fn get_uninitialized_storage_value() {
    let state: CachedState<DictStateReader> = CachedState::default();
    let contract_address = contract_address!("0x1");
    let key = storage_key!(0x10_u16);

    assert_eq!(state.get_storage_at(contract_address, key).unwrap(), Felt::default());
}

#[test]
fn get_and_set_storage_value() {
    let contract_address0 = contract_address!("0x100");
    let contract_address1 = contract_address!("0x200");
    let key0 = storage_key!(0x10_u16);
    let key1 = storage_key!(0x20_u16);
    let storage_val0: Felt = felt!("0x1");
    let storage_val1: Felt = felt!("0x5");

    let mut state = CachedState::from(DictStateReader {
        storage_view: HashMap::from([
            ((contract_address0, key0), storage_val0),
            ((contract_address1, key1), storage_val1),
        ]),
        ..Default::default()
    });
    assert_eq!(state.get_storage_at(contract_address0, key0).unwrap(), storage_val0);
    assert_eq!(state.get_storage_at(contract_address1, key1).unwrap(), storage_val1);

    let modified_storage_value0 = felt!("0xA");
    state.set_storage_at(contract_address0, key0, modified_storage_value0).unwrap();
    assert_eq!(state.get_storage_at(contract_address0, key0).unwrap(), modified_storage_value0);
    assert_eq!(state.get_storage_at(contract_address1, key1).unwrap(), storage_val1);

    let modified_storage_value1 = felt!("0x7");
    state.set_storage_at(contract_address1, key1, modified_storage_value1).unwrap();
    assert_eq!(state.get_storage_at(contract_address0, key0).unwrap(), modified_storage_value0);
    assert_eq!(state.get_storage_at(contract_address1, key1).unwrap(), modified_storage_value1);
}

#[test]
fn cast_between_storage_mapping_types() {
    let empty_map: IndexMap<ContractAddress, IndexMap<StorageKey, Felt>> = IndexMap::default();
    assert_eq!(empty_map, IndexMap::from(StorageView::default()));

    let contract_address0 = contract_address!("0x100");
    let contract_address1 = contract_address!("0x200");
    let key0 = storage_key!(0x10_u16);
    let key1 = storage_key!(0x20_u16);
    let storage_val0: Felt = felt!("0x1");
    let storage_val1: Felt = felt!("0x5");
    let storage_val2: Felt = felt!("0xa");

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
    let state: CachedState<DictStateReader> = CachedState::default();
    let contract_address = contract_address!("0x1");

    assert_eq!(state.get_nonce_at(contract_address).unwrap(), Nonce::default());
}

#[test]
fn declare_contract() {
    let mut state = CachedState::from(DictStateReader { ..Default::default() });
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let class_hash = test_contract.get_class_hash();
    let contract_class = test_contract.get_class();

    assert_eq!(state.cache.borrow().writes.declared_contracts.get(&class_hash), None);
    assert_eq!(state.cache.borrow().initial_reads.declared_contracts.get(&class_hash), None);

    // Reading an undeclared contract class.
    assert_matches!(
        state.get_compiled_contract_class(class_hash).unwrap_err(),
        StateError::UndeclaredClassHash(undeclared_class_hash) if
        undeclared_class_hash == class_hash
    );
    assert_eq!(
        *state.cache.borrow().initial_reads.declared_contracts.get(&class_hash).unwrap(),
        false
    );

    state.set_contract_class(class_hash, contract_class).unwrap();
    assert_eq!(*state.cache.borrow().writes.declared_contracts.get(&class_hash).unwrap(), true);
}

#[test]
fn get_and_increment_nonce() {
    let contract_address1 = contract_address!("0x100");
    let contract_address2 = contract_address!("0x200");
    let initial_nonce = Nonce(felt!(1_u8));

    let mut state = CachedState::from(DictStateReader {
        address_to_nonce: HashMap::from([
            (contract_address1, initial_nonce),
            (contract_address2, initial_nonce),
        ]),
        ..Default::default()
    });
    assert_eq!(state.get_nonce_at(contract_address1).unwrap(), initial_nonce);
    assert_eq!(state.get_nonce_at(contract_address2).unwrap(), initial_nonce);

    assert!(state.increment_nonce(contract_address1).is_ok());
    let nonce1_plus_one = Nonce(felt!(2_u8));
    assert_eq!(state.get_nonce_at(contract_address1).unwrap(), nonce1_plus_one);
    assert_eq!(state.get_nonce_at(contract_address2).unwrap(), initial_nonce);

    assert!(state.increment_nonce(contract_address1).is_ok());
    let nonce1_plus_two = Nonce(felt!(3_u8));
    assert_eq!(state.get_nonce_at(contract_address1).unwrap(), nonce1_plus_two);
    assert_eq!(state.get_nonce_at(contract_address2).unwrap(), initial_nonce);

    assert!(state.increment_nonce(contract_address2).is_ok());
    let nonce2_plus_one = Nonce(felt!(2_u8));
    assert_eq!(state.get_nonce_at(contract_address1).unwrap(), nonce1_plus_two);
    assert_eq!(state.get_nonce_at(contract_address2).unwrap(), nonce2_plus_one);
}

#[test]
fn get_contract_class() {
    // Positive flow.
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 0)]);
    assert_eq!(
        state.get_compiled_contract_class(test_contract.get_class_hash()).unwrap(),
        test_contract.get_class()
    );

    // Negative flow.
    let missing_class_hash = class_hash!("0x101");
    assert_matches!(
        state.get_compiled_contract_class(missing_class_hash).unwrap_err(),
        StateError::UndeclaredClassHash(undeclared) if undeclared == missing_class_hash
    );
}

#[test]
fn get_uninitialized_class_hash_value() {
    let state: CachedState<DictStateReader> = CachedState::default();
    let valid_contract_address = contract_address!("0x1");

    assert_eq!(state.get_class_hash_at(valid_contract_address).unwrap(), ClassHash::default());
}

#[test]
fn set_and_get_contract_hash() {
    let contract_address = contract_address!("0x1");
    let mut state: CachedState<DictStateReader> = CachedState::default();
    let class_hash = class_hash!("0x10");

    assert!(state.set_class_hash_at(contract_address, class_hash).is_ok());
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), class_hash);
}

#[test]
fn cannot_set_class_hash_to_uninitialized_contract() {
    let mut state: CachedState<DictStateReader> = CachedState::default();

    let uninitialized_contract_address = ContractAddress::default();
    let class_hash = class_hash!("0x100");
    assert_matches!(
        state.set_class_hash_at(uninitialized_contract_address, class_hash).unwrap_err(),
        StateError::OutOfRangeContractAddress
    );
}

#[test]
fn cached_state_state_diff_conversion() {
    // This will not appear in the diff, since this mapping is immutable for the current version we
    // are aligned with.
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let test_class_hash = test_contract.get_class_hash();
    let class_hash_to_class = HashMap::from([(test_class_hash, test_contract.get_class())]);

    let nonce_initial_values = HashMap::new();

    // contract_address0 will correspond to keys that are not touched in the test.
    // contract_address1 to keys whose value is overwritten with the same value it previously had
    // (so should not appear in the diff).
    // contract_address2 to keys whose value changes to a different value (so should appear in the
    // diff).
    let contract_address0 = test_contract.get_instance_address(0);
    let contract_address1 = test_contract.get_instance_address(1);
    let contract_address2 = test_contract.get_instance_address(2);

    // key_x will not be changed.
    // key_y will be changed, but only with contract_address2 the value ends up being different, so
    // should only appear with contract_address2.
    let key_x = storage_key!(0x10_u16);
    let key_y = storage_key!(0x20_u16);
    let storage_val0: Felt = felt!("0x1");
    let storage_val1: Felt = felt!("0x5");
    let storage_val2: Felt = felt!("0x6");
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
    let class_hash = FeatureContract::Empty(CairoVersion::Cairo0).get_class_hash();
    let compiled_class_hash = compiled_class_hash!(1_u8);
    // Cache the initial read value, as in regular declare flow.
    state.get_compiled_contract_class(class_hash).unwrap_err();
    state.set_compiled_class_hash(class_hash, compiled_class_hash).unwrap();

    // Write the initial value using key contract_address1.
    state.set_storage_at(contract_address1, key_y, storage_val1).unwrap();

    // Write new values using key contract_address2.
    let new_value = felt!("0x12345678");
    state.set_storage_at(contract_address2, key_y, new_value).unwrap();
    assert!(state.increment_nonce(contract_address2).is_ok());
    let new_class_hash = class_hash!("0x11111111");

    // Cache the initial read value, as in regular deploy flow.
    state.get_class_hash_at(contract_address2).unwrap();
    assert!(state.set_class_hash_at(contract_address2, new_class_hash).is_ok());

    // Only changes to contract_address2 should be shown, since contract_address_0 wasn't changed
    // and contract_address_1 was changed but ended up with the original values.
    let expected_state_diff = CommitmentStateDiff {
        address_to_class_hash: IndexMap::from_iter([(contract_address2, new_class_hash)]),
        storage_updates: IndexMap::from_iter([(contract_address2, indexmap! {key_y => new_value})]),
        class_hash_to_compiled_class_hash: IndexMap::from_iter([(class_hash, compiled_class_hash)]),
        address_to_nonce: IndexMap::from_iter([(contract_address2, nonce!(1_u64))]),
    };

    assert_eq!(expected_state_diff, state.to_state_diff().unwrap().into());
}

fn create_state_changes_for_test<S: StateReader>(
    state: &mut CachedState<S>,
    sender_address: Option<ContractAddress>,
    fee_token_address: ContractAddress,
) -> StateChanges {
    let contract_address = contract_address!(CONTRACT_ADDRESS);
    let contract_address2 = contract_address!("0x101");
    let class_hash = class_hash!("0x10");
    let compiled_class_hash = compiled_class_hash!(0x11_u16);
    let key = storage_key!(0x10_u16);
    let storage_val: Felt = felt!("0x1");

    // Fill the initial read value, as in regular flow.
    state.get_class_hash_at(contract_address).unwrap();
    state.set_class_hash_at(contract_address, class_hash).unwrap();

    state.set_storage_at(contract_address, key, storage_val).unwrap();
    state.increment_nonce(contract_address2).unwrap();

    // Fill the initial read value, as in regular flow.
    state.get_compiled_contract_class(class_hash).unwrap_err();
    state.set_compiled_class_hash(class_hash, compiled_class_hash).unwrap();

    // Assign the existing value to the storage (this shouldn't be considered a change).
    // As the first access:
    state.set_storage_at(contract_address2, key, Felt::default()).unwrap();
    // As the second access:
    state.set_storage_at(contract_address, key, storage_val).unwrap();

    if let Some(sender_address) = sender_address {
        // Charge fee from the sender.
        let sender_balance_key = get_fee_token_var_address(sender_address);
        state.set_storage_at(fee_token_address, sender_balance_key, felt!("0x1999")).unwrap();
    }

    state.get_actual_state_changes().unwrap()
}

#[rstest]
fn test_from_state_changes_for_fee_charge(
    #[values(Some(contract_address!("0x102")), None)] sender_address: Option<ContractAddress>,
) {
    let mut state: CachedState<DictStateReader> = CachedState::default();
    let fee_token_address = contract_address!("0x17");
    let state_changes =
        create_state_changes_for_test(&mut state, sender_address, fee_token_address);
    let state_changes_count = state_changes.count_for_fee_charge(sender_address, fee_token_address);
    let expected_state_changes_count = StateChangesCount {
        // 1 for storage update + 1 for sender balance update if sender is defined.
        n_storage_updates: 1 + usize::from(sender_address.is_some()),
        n_class_hash_updates: 1,
        n_compiled_class_hash_updates: 1,
        n_modified_contracts: 2,
    };
    assert_eq!(state_changes_count, expected_state_changes_count);
}

#[rstest]
fn test_state_changes_merge(
    #[values(Some(contract_address!("0x102")), None)] sender_address: Option<ContractAddress>,
) {
    // Create a transactional state containing the `create_state_changes_for_test` logic, get the
    // state changes and then commit.
    let mut state: CachedState<DictStateReader> = CachedState::default();
    let mut transactional_state = TransactionalState::create_transactional(&mut state);
    let block_context = BlockContext::create_for_testing();
    let fee_token_address = block_context.chain_info.fee_token_addresses.eth_fee_token_address;
    let state_changes1 =
        create_state_changes_for_test(&mut transactional_state, sender_address, fee_token_address);
    transactional_state.commit();

    // After performing `commit`, the transactional state is moved (into state).  We need to create
    // a new transactional state that wraps `state` to continue.
    let mut transactional_state = TransactionalState::create_transactional(&mut state);
    // Make sure that `get_actual_state_changes` on a newly created transactional state returns null
    // state changes and that merging null state changes with non-null state changes results in the
    // non-null state changes, no matter the order.
    let state_changes2 = transactional_state.get_actual_state_changes().unwrap();
    assert_eq!(state_changes2, StateChanges::default());
    assert_eq!(
        StateChanges::merge(vec![state_changes1.clone(), state_changes2.clone()]),
        state_changes1
    );
    assert_eq!(
        StateChanges::merge(vec![state_changes2.clone(), state_changes1.clone()]),
        state_changes1
    );

    // Get the storage updates addresses and keys from the state_changes1, to overwrite.
    let mut storage_updates_keys = state_changes1.0.storage.keys();
    let &(contract_address, storage_key) = storage_updates_keys
        .find(|(contract_address, _)| contract_address == &contract_address!(CONTRACT_ADDRESS))
        .unwrap();
    // A new address, not included in state_changes1, to write to.
    let new_contract_address = ContractAddress(patricia_key!("0x111"));

    // Overwrite existing and new storage values.
    transactional_state.set_storage_at(contract_address, storage_key, felt!("0x1234")).unwrap();
    transactional_state
        .set_storage_at(new_contract_address, storage_key, felt!("0x43210"))
        .unwrap();
    transactional_state.increment_nonce(contract_address).unwrap();
    // Get the new state changes and then commit the transactional state.
    let state_changes3 = transactional_state.get_actual_state_changes().unwrap();
    transactional_state.commit();

    // Get the total state changes of the CachedState underlying all the temporary transactional
    // states. We expect the state_changes to match the merged state_changes of the transactional
    // states, but only when done in the right order.
    let state_changes_final = state.get_actual_state_changes().unwrap();
    assert_eq!(
        StateChanges::merge(vec![
            state_changes1.clone(),
            state_changes2.clone(),
            state_changes3.clone()
        ]),
        state_changes_final
    );
    assert_ne!(
        StateChanges::merge(vec![state_changes3, state_changes1, state_changes2]),
        state_changes_final
    );
}

#[test]
fn test_contract_cache_is_used() {
    // Initialize the global cache with a single class, and initialize an empty state with this
    // cache.
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let class_hash = test_contract.get_class_hash();
    let contract_class = test_contract.get_class();
    let mut reader = DictStateReader::default();
    reader.class_hash_to_class.insert(class_hash, contract_class.clone());
    let state = CachedState::new(reader);

    // Assert local cache is initialized empty.
    assert!(state.class_hash_to_class.borrow().get(&class_hash).is_none());

    // Check state uses the cache.
    assert_eq!(state.get_compiled_contract_class(class_hash).unwrap(), contract_class);
    assert_eq!(state.class_hash_to_class.borrow().get(&class_hash).unwrap(), &contract_class);
}

#[test]
fn test_cache_get_write_keys() {
    // Trivial case.
    assert_eq!(StateChanges::default().into_keys(), StateChangesKeys::default());

    // Interesting case.
    let some_felt = felt!("0x1");
    let some_class_hash = class_hash!("0x1");

    let contract_address0 = contract_address!("0x200");
    let contract_address1 = contract_address!("0x201");
    let contract_address2 = contract_address!("0x202");
    let contract_address3 = contract_address!("0x203");

    let class_hash0 = class_hash!("0x300");

    let state_changes = StateChanges(StateMaps {
        nonces: HashMap::from([(contract_address0, Nonce(some_felt))]),
        class_hashes: HashMap::from([
            (contract_address1, some_class_hash),
            (contract_address2, some_class_hash),
        ]),
        storage: HashMap::from([
            ((contract_address1, storage_key!(0x300_u16)), some_felt),
            ((contract_address1, storage_key!(0x600_u16)), some_felt),
            ((contract_address3, storage_key!(0x600_u16)), some_felt),
        ]),
        compiled_class_hashes: HashMap::from([(class_hash0, compiled_class_hash!(0x3_u16))]),
        declared_contracts: HashMap::default(),
    });

    let expected_keys = StateChangesKeys {
        nonce_keys: HashSet::from([contract_address0]),
        class_hash_keys: HashSet::from([contract_address1, contract_address2]),
        storage_keys: HashSet::from([
            (contract_address1, storage_key!(0x300_u16)),
            (contract_address1, storage_key!(0x600_u16)),
            (contract_address3, storage_key!(0x600_u16)),
        ]),
        compiled_class_hash_keys: HashSet::from([class_hash0]),
        modified_contracts: HashSet::from([
            contract_address0,
            contract_address1,
            contract_address2,
            contract_address3,
        ]),
    };

    assert_eq!(state_changes.into_keys(), expected_keys);
}

#[test]
fn test_state_changes_keys() {
    let contract_address0 = contract_address!("0x200");
    let contract_address1 = contract_address!("0x201");
    let contract_address2 = contract_address!("0x202");
    let contract_address3 = contract_address!("0x203");

    let class_hash0 = class_hash!("0x300");
    let class_hash1 = class_hash!("0x301");

    let empty_keys = StateChangesKeys::default();
    let mut keys0 = StateChangesKeys {
        nonce_keys: HashSet::from([contract_address0]),
        class_hash_keys: HashSet::from([contract_address1]),
        storage_keys: HashSet::from([
            (contract_address2, storage_key!(0x300_u16)),
            (contract_address2, storage_key!(0x200_u16)),
        ]),
        compiled_class_hash_keys: HashSet::from([class_hash0, class_hash1]),
        modified_contracts: HashSet::from([contract_address1, contract_address2]),
    };

    // Trivial cases.
    assert_eq!(empty_keys, empty_keys.difference(&keys0));
    assert_eq!(keys0, keys0.difference(&empty_keys));
    assert_eq!(empty_keys, keys0.difference(&keys0));
    assert_eq!(empty_keys.count(), StateChangesCount::default());
    assert_eq!(
        keys0.count(),
        StateChangesCount {
            n_storage_updates: 2,
            n_class_hash_updates: 1,
            n_compiled_class_hash_updates: 2,
            n_modified_contracts: 2
        }
    );

    let mut keys0_copy = keys0.clone();
    let mut empty_keys_copy = empty_keys.clone();
    keys0_copy.extend(&empty_keys);
    empty_keys_copy.extend(&keys0);

    assert_eq!(keys0, keys0_copy);
    assert_eq!(keys0, empty_keys_copy);

    // Interesting cases.
    let mut keys1 = StateChangesKeys {
        nonce_keys: HashSet::from([contract_address1]),
        class_hash_keys: HashSet::from([contract_address1, contract_address2]),
        storage_keys: HashSet::from([(contract_address2, storage_key!(0x300_u16))]),
        compiled_class_hash_keys: HashSet::from([class_hash0]),
        modified_contracts: HashSet::from([contract_address1, contract_address3]),
    };

    assert_eq!(
        keys0.difference(&keys1),
        StateChangesKeys {
            nonce_keys: HashSet::from([contract_address0]),
            class_hash_keys: HashSet::new(),
            storage_keys: HashSet::from([(contract_address2, storage_key!(0x200_u16),)]),
            compiled_class_hash_keys: HashSet::from([class_hash1]),
            modified_contracts: HashSet::from([contract_address2]),
        }
    );
    assert_eq!(
        keys1.difference(&keys0),
        StateChangesKeys {
            nonce_keys: HashSet::from([contract_address1]),
            class_hash_keys: HashSet::from([contract_address2]),
            storage_keys: HashSet::new(),
            compiled_class_hash_keys: HashSet::new(),
            modified_contracts: HashSet::from([contract_address3]),
        }
    );

    let keys1_copy = keys1.clone();
    keys1.extend(&keys0);
    keys0.extend(&keys1_copy);
    assert_eq!(keys0, keys1);
    assert_eq!(
        keys0,
        StateChangesKeys {
            nonce_keys: HashSet::from([contract_address0, contract_address1]),
            class_hash_keys: HashSet::from([contract_address1, contract_address2]),
            storage_keys: HashSet::from([
                (contract_address2, storage_key!(0x300_u16)),
                (contract_address2, storage_key!(0x200_u16)),
            ]),
            compiled_class_hash_keys: HashSet::from([class_hash0, class_hash1]),
            modified_contracts: HashSet::from([
                contract_address1,
                contract_address2,
                contract_address3
            ]),
        }
    )
}

#[rstest]
fn test_state_maps() {
    let contract_address1 = contract_address!("0x101");
    let storage_key1 = storage_key!(0x102_u16);
    let class_hash1 = class_hash!("0x103");
    let nonce1 = Nonce(felt!(0x104_u16));
    let compiled_class_hash1 = compiled_class_hash!(0x105_u16);
    let some_felt1 = felt!("0x106");
    let maps = StateMaps {
        nonces: HashMap::from([(contract_address1, nonce1)]),
        class_hashes: HashMap::from([(contract_address1, class_hash1)]),
        storage: HashMap::from([((contract_address1, storage_key1), some_felt1)]),
        compiled_class_hashes: HashMap::from([(class_hash1, compiled_class_hash1)]),
        declared_contracts: HashMap::from([(class_hash1, true)]),
    };

    // Test that `extend` extends all hash maps (by constructing `maps` without default values).
    let mut empty = StateMaps::default();
    empty.extend(&maps);

    assert_eq!(maps, empty);
}
