use std::collections::HashMap;

use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::{contract_address, patricia_key, stark_felt};

use crate::concurrency::versioned_state::VersionedState;

#[test]
fn test_versioned_state() {
    let mut versioned_cache_state = VersionedState::new(
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
    );

    // Test data
    let contract_address = contract_address!("0x1");
    let key = StorageKey(patricia_key!("0x10"));
    let nonce = Nonce(stark_felt!(20_u8));
    let class_hash = ClassHash(stark_felt!(27_u8));
    let compiled_class_hash = CompiledClassHash(stark_felt!(29_u8));

    // Write initial data to the state.
    versioned_cache_state.set_storage_at(contract_address, key, stark_felt!(23_u8), 0);
    versioned_cache_state.set_nonce_at(contract_address, nonce, 0);
    versioned_cache_state.set_class_hash_at(contract_address, class_hash, 0);
    versioned_cache_state.set_compiled_class_hash(class_hash, compiled_class_hash, 0);

    // Read the data
    let result = versioned_cache_state.get_nonce_at(contract_address, 0);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), nonce);

    let result = versioned_cache_state.get_nonce_at(contract_address, 10);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), nonce);

    // Write new data.
    let new_compiled_class_hash = CompiledClassHash(stark_felt!(100_u8));
    versioned_cache_state.set_compiled_class_hash(class_hash, new_compiled_class_hash, 5);

    // Read old data
    let result = versioned_cache_state.get_compiled_class_hash(class_hash, 2);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), compiled_class_hash);

    // Read new data
    let result = versioned_cache_state.get_compiled_class_hash(class_hash, 7);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), new_compiled_class_hash);
}
