use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// use std::thread;
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::{contract_address, patricia_key, stark_felt};

use crate::concurrency::concurrency_utils::{transaction_commit, validate_read_set};
use crate::concurrency::versioned_client_state::VersionedClientState;
use crate::concurrency::versioned_state::VersionedState;
use crate::state::cached_state::CachedState;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::dict_state_reader::DictStateReader;

fn versioned_state_for_testing(
    contract_address: ContractAddress,
    class_hash: ClassHash,
) -> Arc<Mutex<VersionedState<CachedState<DictStateReader>>>> {
    // Initialize the versioned state.
    let mut address_to_class_hash = HashMap::new();
    address_to_class_hash.insert(contract_address, class_hash);

    let cached_state =
        CachedState::from(DictStateReader { address_to_class_hash, ..Default::default() });
    Arc::new(Mutex::new(VersionedState::new(cached_state)))
}

#[test]
fn test_versioned_client_state_flow() {
    let contract_address = contract_address!("0x1");
    let init_class_hash = ClassHash(stark_felt!(27_u8));
    let mut versioned_state = versioned_state_for_testing(contract_address, init_class_hash);
    let mut unupdated_versioned_state =
        versioned_state_for_testing(contract_address!("0x2"), init_class_hash);

    let transactional_state_0 =
        CachedState::from(VersionedClientState::new(0, Arc::clone(&versioned_state)));
    let mut transactional_state_1 =
        CachedState::from(VersionedClientState::new(1, Arc::clone(&versioned_state)));
    let mut transactional_state_2 =
        CachedState::from(VersionedClientState::new(2, Arc::clone(&versioned_state)));
    let transactional_state_3 =
        CachedState::from(VersionedClientState::new(3, Arc::clone(&versioned_state)));

    let _ = transactional_state_1.get_class_hash_at(contract_address);
    let _ = transactional_state_1.get_nonce_at(contract_address);

    assert!(validate_read_set(1, &mut transactional_state_1, &mut versioned_state));
    assert!(!validate_read_set(1, &mut transactional_state_1, &mut unupdated_versioned_state));

    // Clients class hash values.
    let class_hash_1 = ClassHash(stark_felt!(76_u8));
    let class_hash_2 = ClassHash(stark_felt!(234_u8));

    let _ = transactional_state_1.set_class_hash_at(contract_address, class_hash_1);

    // Validate Read set.
    assert!(validate_read_set(1, &mut transactional_state_1, &mut versioned_state));
    assert!(!validate_read_set(1, &mut transactional_state_1, &mut unupdated_versioned_state));

    // TX 2 does not read the value written by TX 1 till TX 1 is committed.
    assert!(transactional_state_2.get_class_hash_at(contract_address).unwrap() == init_class_hash);

    transaction_commit(1, &mut transactional_state_1, &mut versioned_state);
    assert!(transactional_state_3.get_class_hash_at(contract_address).unwrap() == class_hash_1);

    // TX 2 reads the value from its cache.
    // To read the value written by TX 1 it needs to be re-executed.
    assert!(transactional_state_2.get_class_hash_at(contract_address).unwrap() == init_class_hash);

    // Re-execute TX 2.
    transactional_state_2 =
        CachedState::from(VersionedClientState::new(1, Arc::clone(&versioned_state)));
    assert!(transactional_state_2.get_class_hash_at(contract_address).unwrap() == class_hash_1);

    let _ = transactional_state_2.set_class_hash_at(contract_address, class_hash_2);
    assert!(transactional_state_2.get_class_hash_at(contract_address).unwrap() == class_hash_2);

    // Verify the versioning mechanism is working.
    assert!(transactional_state_0.get_class_hash_at(contract_address).unwrap() == init_class_hash);
}
