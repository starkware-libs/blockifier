use std::sync::{Arc, Mutex};

use super::versioned_client_state::VersionedClientState;
use crate::concurrency::versioned_state::VersionedState;
use crate::concurrency::versioned_storage::Version;
use crate::state::cached_state::CachedState;
use crate::state::state_api::StateReader;

#[cfg(test)]
#[path = "concurrency_utils_test.rs"]
pub mod test;

pub fn validate_read_set<S: StateReader>(
    version: Version,
    transactional_state: &mut CachedState<VersionedClientState<CachedState<S>>>,
    versioned_state: &mut Arc<Mutex<VersionedState<CachedState<S>>>>,
) -> bool {
    // Iterate through each entry in the read set.
    let cache = transactional_state.cache.borrow();

    for (key, expected_value) in &cache.storage_initial_values {
        let value = versioned_state.lock().unwrap().get_storage_at(version, key.0, key.1);
        assert!(value.is_ok());
        if expected_value != &value.unwrap() {
            return false;
        }
    }

    for (key, expected_value) in &cache.nonce_initial_values {
        let value = versioned_state.lock().unwrap().get_nonce_at(version, *key);
        assert!(value.is_ok());
        if expected_value != &value.unwrap() {
            return false;
        }
    }

    for (key, expected_value) in &cache.class_hash_initial_values {
        let value = versioned_state.lock().unwrap().get_class_hash_at(version, *key);
        assert!(value.is_ok());
        if expected_value != &value.unwrap() {
            return false;
        }
    }

    for (key, expected_value) in &cache.compiled_class_hash_initial_values {
        let value = versioned_state.lock().unwrap().get_compiled_class_hash(version, *key);
        assert!(value.is_ok());
        if expected_value != &value.unwrap() {
            return false;
        }
    }

    let class_hash_to_class = transactional_state.class_hash_to_class.borrow();
    for (key, expected_value) in &*class_hash_to_class {
        let value = versioned_state.lock().unwrap().get_compiled_contract_class(version, *key);
        assert!(value.is_ok());
        if expected_value != &value.unwrap() {
            return false;
        }
    }
    // All values in the read set match the values from versioned state, return true.
    true
}

/// Note: This function should be called after `update_initial_values_of_write_only_access`.
pub fn apply_writes<S: StateReader>(
    version: Version,
    transactional_state: &mut CachedState<VersionedClientState<CachedState<S>>>,
    versioned_state: &mut Arc<Mutex<VersionedState<CachedState<S>>>>,
) {
    let cache = transactional_state.cache.borrow();

    for (key, value) in &cache.storage_writes {
        versioned_state.lock().unwrap().set_storage_at(version, key.0, key.1, *value);
    }

    for (key, value) in &cache.nonce_writes {
        versioned_state.lock().unwrap().set_nonce_at(version, *key, *value);
    }

    for (key, value) in &cache.class_hash_writes {
        versioned_state.lock().unwrap().set_class_hash_at(version, *key, *value);
    }

    for (key, value) in &cache.compiled_class_hash_writes {
        versioned_state.lock().unwrap().set_compiled_class_hash(version, *key, *value);
    }

    let class_hash_to_class = transactional_state.class_hash_to_class.borrow();
    for (key, value) in &*class_hash_to_class {
        versioned_state.lock().unwrap().set_compiled_contract_class(version, *key, value.clone());
    }
}
