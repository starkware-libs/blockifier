use std::collections::HashMap;

use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::{contract_address, patricia_key, stark_felt};

use crate::concurrency::versioned_state::VersionedState;
use crate::state::cached_state::CachedState;
use crate::test_utils::dict_state_reader::DictStateReader;

#[test]
fn test_versioned_state() {
    // Test data
    let contract_address = contract_address!("0x1");
    let key = StorageKey(patricia_key!("0x10"));
    let stark_felt = stark_felt!(13_u8);
    let nonce = Nonce(stark_felt!(2_u8));
    let class_hash = ClassHash(stark_felt!(27_u8));
    let compiled_class_hash = CompiledClassHash(stark_felt!(29_u8));

    let mut storage_view = HashMap::new();
    storage_view.insert((contract_address, key), stark_felt);
    let mut address_to_nonce = HashMap::new();
    address_to_nonce.insert(contract_address, nonce);
    let mut address_to_class_hash = HashMap::new();
    address_to_class_hash.insert(contract_address, class_hash);
    let mut class_hash_to_compiled_class_hash = HashMap::new();
    class_hash_to_compiled_class_hash.insert(class_hash, compiled_class_hash);

    let cached_state = CachedState::from(DictStateReader {
        storage_view,
        address_to_nonce,
        address_to_class_hash,
        class_hash_to_compiled_class_hash,
        ..Default::default()
    });
    let mut versioned_cache_state = VersionedState::new(cached_state);

    // Read initial data
    assert_eq!(versioned_cache_state.get_nonce_at(contract_address, 5).unwrap(), nonce);
    assert_eq!(versioned_cache_state.get_nonce_at(contract_address, 0).unwrap(), nonce);
    assert_eq!(versioned_cache_state.get_storage_at(contract_address, key, 7).unwrap(), stark_felt);
    assert_eq!(versioned_cache_state.get_class_hash_at(contract_address, 2).unwrap(), class_hash);
    assert_eq!(
        versioned_cache_state.get_compiled_class_hash(class_hash, 97).unwrap(),
        compiled_class_hash
    );

    // Write to the state.
    let new_key = StorageKey(patricia_key!("0x11"));
    let new_stark_felt = stark_felt!(14_u8);
    let new_nonce = Nonce(stark_felt!(3_u8));
    let new_class_hash_7 = ClassHash(stark_felt!(28_u8));
    let new_class_hash_10 = ClassHash(stark_felt!(29_u8));
    let new_compiled_class_hash = CompiledClassHash(stark_felt!(30_u8));

    versioned_cache_state.set_storage_at(contract_address, new_key, new_stark_felt, 3);
    versioned_cache_state.set_nonce_at(contract_address, new_nonce, 4);
    versioned_cache_state.set_class_hash_at(contract_address, new_class_hash_7, 7);
    versioned_cache_state.set_class_hash_at(contract_address, new_class_hash_10, 10);
    versioned_cache_state.set_compiled_class_hash(class_hash, new_compiled_class_hash, 21);

    // Read the data
    assert_eq!(versioned_cache_state.get_nonce_at(contract_address, 2).unwrap(), nonce);
    assert_eq!(versioned_cache_state.get_nonce_at(contract_address, 5).unwrap(), new_nonce);

    assert_eq!(versioned_cache_state.get_storage_at(contract_address, key, 5).unwrap(), stark_felt);
    assert_eq!(
        versioned_cache_state.get_storage_at(contract_address, new_key, 5).unwrap(),
        new_stark_felt
    );

    assert_eq!(versioned_cache_state.get_class_hash_at(contract_address, 2).unwrap(), class_hash);
    assert_eq!(
        versioned_cache_state.get_class_hash_at(contract_address, 9).unwrap(),
        new_class_hash_7
    );
    assert_eq!(
        versioned_cache_state.get_class_hash_at(contract_address, 10).unwrap(),
        new_class_hash_10
    );

    assert_eq!(
        versioned_cache_state.get_compiled_class_hash(class_hash, 2).unwrap(),
        compiled_class_hash
    );
    assert_eq!(
        versioned_cache_state.get_compiled_class_hash(class_hash, 100).unwrap(),
        new_compiled_class_hash
    );
}
