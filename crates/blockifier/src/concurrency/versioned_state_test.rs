use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::{contract_address, patricia_key, stark_felt};

use crate::concurrency::versioned_state::VersionedState;
use crate::state::cached_state::CachedState;
use crate::test_utils::dict_state_reader::DictStateReader;
// use crate::test_utils::dict_state_reader::DictStateReader;

#[test]
fn test_versioned_state() {
    let cached_state = Box::<CachedState<DictStateReader>>::default();
    let cached_state_static: &'static CachedState<DictStateReader> = Box::leak(cached_state);
    let mut versioned_cache_state = VersionedState::new(cached_state_static);

    // Test data
    let contract_address = contract_address!("0x1");
    let key = StorageKey(patricia_key!("0x10"));
    let nonce = Nonce(stark_felt!(20_u8));
    let class_hash = ClassHash(stark_felt!(27_u8));
    let compiled_class_hash = CompiledClassHash(stark_felt!(29_u8));

    // Write initial data to the state.
    let res = versioned_cache_state.set_storage_at(contract_address, key, stark_felt!(23_u8), 0);
    assert!(res.is_ok());

    let res = versioned_cache_state.set_nonce_at(contract_address, nonce, 0);
    assert!(res.is_ok());

    let res = versioned_cache_state.set_class_hash_at(contract_address, class_hash, 0);
    assert!(res.is_ok());

    let res = versioned_cache_state.set_compiled_class_hash_at(class_hash, compiled_class_hash, 0);
    assert!(res.is_ok());

    // Read the data
    let result = versioned_cache_state.get_nonce_at(contract_address, 0);
    assert!(res.is_ok());
    assert_eq!(result.unwrap(), nonce);

    let result = versioned_cache_state.get_nonce_at(contract_address, 10);
    assert!(res.is_ok());
    assert_eq!(result.unwrap(), nonce);

    // Write new data.
    let new_compiled_class_hash = CompiledClassHash(stark_felt!(100_u8));
    let res =
        versioned_cache_state.set_compiled_class_hash_at(class_hash, new_compiled_class_hash, 5);
    assert!(res.is_ok());

    // Read old data
    let result = versioned_cache_state.get_compiled_class_hash_at(class_hash, 2);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), compiled_class_hash);

    // Read new data
    let result = versioned_cache_state.get_compiled_class_hash_at(class_hash, 7);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), new_compiled_class_hash);
}
