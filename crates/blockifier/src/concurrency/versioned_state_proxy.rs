use std::sync::{Arc, Mutex, MutexGuard};

use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::concurrency::versioned_storage::VersionedStorage;
use crate::concurrency::Version;
use crate::execution::contract_class::ContractClass;
use crate::state::cached_state::CachedState;
use crate::state::state_api::{StateReader, StateResult};

#[cfg(test)]
#[path = "versioned_state_proxy_test.rs"]
pub mod test;

/// A collection of versioned storages.
/// Represents a versioned state used as shared state between a chunk of workers.
/// This state facilitates concurrent operations.
/// Reader functionality is injected through initial state.
pub struct VersionedState<S: StateReader> {
    initial_state: S,
    storage: VersionedStorage<(ContractAddress, StorageKey), StarkFelt>,
    nonces: VersionedStorage<ContractAddress, Nonce>,
    class_hashes: VersionedStorage<ContractAddress, ClassHash>,
    compiled_class_hashes: VersionedStorage<ClassHash, CompiledClassHash>,
    compiled_contract_classes: VersionedStorage<ClassHash, ContractClass>,
}

impl<S: StateReader> VersionedState<S> {
    pub fn new(initial_state: S) -> Self {
        VersionedState {
            initial_state,
            storage: VersionedStorage::default(),
            nonces: VersionedStorage::default(),
            class_hashes: VersionedStorage::default(),
            compiled_class_hashes: VersionedStorage::default(),
            compiled_contract_classes: VersionedStorage::default(),
        }
    }

    pub fn validate_read_set(
        &mut self,
        version: Version,
        transactional_state: &mut CachedState<VersionedStateProxy<CachedState<S>>>,
        // versioned_state: &mut Arc<Mutex<VersionedState<CachedState<S>>>>,
    ) -> bool {
        let cache = transactional_state.cache.borrow();
        for ((contract_address, storage_key), expected_value) in &cache.storage_initial_values {
            let value = match self.storage.read(version - 1, (*contract_address, *storage_key)) {
                Some(value) => Ok(value),
                None => self.initial_state.get_storage_at(*contract_address, *storage_key),
            };
            if *expected_value != value.unwrap() {
                return false;
            }
        }
        for (contract_address, expected_value) in &cache.nonce_initial_values {
            let value = match self.nonces.read(version - 1, *contract_address) {
                Some(value) => Ok(value),
                None => self.initial_state.get_nonce_at(*contract_address),
            };
            if *expected_value != value.unwrap() {
                return false;
            }
        }
        for (contract_address, expected_value) in &cache.class_hash_initial_values {
            let value = match self.class_hashes.read(version - 1, *contract_address) {
                Some(value) => Ok(value),
                None => self.initial_state.get_class_hash_at(*contract_address),
            };
            if *expected_value != value.unwrap() {
                return false;
            }
        }
        for (class_hash, expected_value) in &cache.compiled_class_hash_initial_values {
            let value = match self.compiled_class_hashes.read(version - 1, *class_hash) {
                Some(value) => Ok(value),
                None => self.initial_state.get_compiled_class_hash(*class_hash),
            };
            if *expected_value != value.unwrap() {
                return false;
            }
        }
        let class_hash_to_class = transactional_state.class_hash_to_class.borrow();
        for (class_hash, expected_value) in &*class_hash_to_class {
            let value = match self.compiled_contract_classes.read(version - 1, *class_hash) {
                Some(value) => Ok(value),
                None => self.initial_state.get_compiled_contract_class(*class_hash),
            };
            if *expected_value != value.unwrap() {
                return false;
            }
        }
        // All values in the read set match the values from versioned state, return true.
        true
    }

    pub fn apply_writes(
        &mut self,
        version: Version,
        transactional_state: &mut CachedState<VersionedStateProxy<CachedState<S>>>,
    ) {
        let cache = transactional_state.cache.borrow();

        for (key, value) in &cache.storage_writes {
            self.storage.write(version, *key, *value);
        }
        for (key, value) in &cache.nonce_writes {
            self.nonces.write(version, *key, *value);
        }
        for (key, value) in &cache.class_hash_writes {
            self.class_hashes.write(version, *key, *value);
        }
        for (key, value) in &cache.compiled_class_hash_writes {
            self.compiled_class_hashes.write(version, *key, *value);
        }
        let class_hash_to_class = transactional_state.class_hash_to_class.borrow();
        for (key, value) in &*class_hash_to_class {
            self.compiled_contract_classes.write(version, *key, value.clone());
        }
    }
}

pub struct ThreadSafeVersionedState<S: StateReader>(Arc<Mutex<VersionedState<S>>>);

impl<S: StateReader> ThreadSafeVersionedState<S> {
    pub fn checkout(&self, version: Version) -> VersionedStateProxy<S> {
        VersionedStateProxy { version, state: self.0.clone() }
    }
}

pub struct VersionedStateProxy<S: StateReader> {
    pub version: Version,
    pub state: Arc<Mutex<VersionedState<S>>>,
}

impl<S: StateReader> VersionedStateProxy<S> {
    fn state(&self) -> MutexGuard<'_, VersionedState<S>> {
        self.state.lock().expect("Failed to acquire state lock.")
    }

    // Writes
    pub fn set_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) {
        let mut state = self.state();
        state.storage.write(self.version, (contract_address, key), value);
    }

    pub fn set_class_hash_at(&mut self, contract_address: ContractAddress, class_hash: ClassHash) {
        let mut state = self.state();
        state.class_hashes.write(self.version, contract_address, class_hash);
    }

    pub fn set_nonce_at(&mut self, contract_address: ContractAddress, nonce: Nonce) {
        let mut state = self.state();
        state.nonces.write(self.version, contract_address, nonce);
    }

    pub fn set_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
    ) {
        let mut state = self.state();
        state.compiled_class_hashes.write(self.version, class_hash, compiled_class_hash);
    }

    pub fn set_compiled_contract_class(
        &mut self,
        class_hash: ClassHash,
        contract_class: ContractClass,
    ) {
        let mut state = self.state();
        state.compiled_contract_classes.write(self.version, class_hash, contract_class);
    }
}

impl<S: StateReader> StateReader for VersionedStateProxy<S> {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        let mut state = self.state();
        match state.storage.read(self.version, (contract_address, key)) {
            Some(value) => Ok(value),
            None => {
                let initial_value = state.initial_state.get_storage_at(contract_address, key)?;
                state.storage.set_initial_value((contract_address, key), initial_value);
                Ok(initial_value)
            }
        }
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        let mut state = self.state();
        match state.nonces.read(self.version, contract_address) {
            Some(value) => Ok(value),
            None => {
                let initial_value = state.initial_state.get_nonce_at(contract_address)?;
                state.nonces.set_initial_value(contract_address, initial_value);
                Ok(initial_value)
            }
        }
    }

    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        let mut state = self.state();
        match state.class_hashes.read(self.version, contract_address) {
            Some(value) => Ok(value),
            None => {
                let initial_value = state.initial_state.get_class_hash_at(contract_address)?;
                state.class_hashes.set_initial_value(contract_address, initial_value);
                Ok(initial_value)
            }
        }
    }

    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        let mut state = self.state();
        match state.compiled_class_hashes.read(self.version, class_hash) {
            Some(value) => Ok(value),
            None => {
                let initial_value = state.initial_state.get_compiled_class_hash(class_hash)?;
                state.compiled_class_hashes.set_initial_value(class_hash, initial_value);
                Ok(initial_value)
            }
        }
    }

    fn get_compiled_contract_class(&self, class_hash: ClassHash) -> StateResult<ContractClass> {
        let mut state = self.state();
        match state.compiled_contract_classes.read(self.version, class_hash) {
            Some(value) => Ok(value),
            None => {
                let initial_value = state.initial_state.get_compiled_contract_class(class_hash)?;
                state
                    .compiled_contract_classes
                    .set_initial_value(class_hash, initial_value.clone());
                Ok(initial_value)
            }
        }
    }
}
