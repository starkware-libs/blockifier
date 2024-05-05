use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::concurrency::versioned_storage::VersionedStorage;
use crate::concurrency::TxIndex;
use crate::execution::contract_class::ContractClass;
use crate::state::cached_state::{CachedState, ContractClassMapping, StateMaps};
use crate::state::state_api::{StateReader, StateResult};

#[cfg(test)]
#[path = "versioned_state_proxy_test.rs"]
pub mod test;

const READ_ERR: &str = "Error: read value missing in the versioned storage";

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

    pub fn get_writes(&mut self, from_index: TxIndex) -> StateMaps {
        StateMaps {
            storage: self.storage.get_writes_from_index(from_index),
            nonces: self.nonces.get_writes_from_index(from_index),
            class_hashes: self.class_hashes.get_writes_from_index(from_index),
            compiled_class_hashes: self.compiled_class_hashes.get_writes_from_index(from_index),
            declared_contracts: HashMap::new(),
        }
    }

    pub fn commit<T>(&mut self, from_index: TxIndex, parent_state: &mut CachedState<T>)
    where
        T: StateReader,
    {
        let writes = self.get_writes(from_index);
        parent_state.update_cache(writes);

        parent_state.update_contract_class_cache(
            self.compiled_contract_classes.get_writes_from_index(from_index),
        );
    }

    // TODO(Mohammad, 01/04/2024): Store the read set (and write set) within a shared
    // object (probabily `VersionedState`). As RefCell operations are not thread-safe. Therefore,
    // accessing this function should be protected by a mutex to ensure thread safety.
    pub fn validate_read_set(&mut self, tx_index: TxIndex, reads: &StateMaps) -> bool {
        // If is the first transaction in the chunk, then the read set is valid. Since it has no
        // predecessors, there's nothing to compare it to.
        if tx_index == 0 {
            return true;
        }

        for (&(contract_address, storage_key), expected_value) in &reads.storage {
            let value =
                self.storage.read(tx_index, (contract_address, storage_key)).expect(READ_ERR);

            if &value != expected_value {
                return false;
            }
        }

        for (&contract_address, expected_value) in &reads.nonces {
            let value = self.nonces.read(tx_index, contract_address).expect(READ_ERR);

            if &value != expected_value {
                return false;
            }
        }

        for (&contract_address, expected_value) in &reads.class_hashes {
            let value = self.class_hashes.read(tx_index, contract_address).expect(READ_ERR);

            if &value != expected_value {
                return false;
            }
        }

        // Added for symmetry. We currently do not update this initial mapping.
        for (&class_hash, expected_value) in &reads.compiled_class_hashes {
            let value = self.compiled_class_hashes.read(tx_index, class_hash).expect(READ_ERR);

            if &value != expected_value {
                return false;
            }
        }

        // TODO(Mohammad, 01/04/2024): Edit the code to handle the case of a deploy preceding a
        // decalre transaction.

        // All values in the read set match the values from versioned state, return true.
        true
    }

    pub fn apply_writes(
        &mut self,
        tx_index: TxIndex,
        writes: &StateMaps,
        class_hash_to_class: &ContractClassMapping,
    ) {
        for (&key, &value) in &writes.storage {
            self.storage.write(tx_index, key, value);
        }
        for (&key, &value) in &writes.nonces {
            self.nonces.write(tx_index, key, value);
        }
        for (&key, &value) in &writes.class_hashes {
            self.class_hashes.write(tx_index, key, value);
        }
        for (&key, &value) in &writes.compiled_class_hashes {
            self.compiled_class_hashes.write(tx_index, key, value);
        }
        for (&key, value) in class_hash_to_class {
            self.compiled_contract_classes.write(tx_index, key, value.clone());
        }
    }
}

pub struct ThreadSafeVersionedState<S: StateReader>(Arc<Mutex<VersionedState<S>>>);
pub type LockedVersionedState<'a, S> = MutexGuard<'a, VersionedState<S>>;

impl<S: StateReader> ThreadSafeVersionedState<S> {
    pub fn pin_version(&self, tx_index: TxIndex) -> VersionedStateProxy<S> {
        VersionedStateProxy { tx_index, state: self.0.clone() }
    }
}

pub struct VersionedStateProxy<S: StateReader> {
    pub tx_index: TxIndex,
    pub state: Arc<Mutex<VersionedState<S>>>,
}

impl<S: StateReader> VersionedStateProxy<S> {
    pub fn state(&self) -> LockedVersionedState<'_, S> {
        self.state.lock().expect("Failed to acquire state lock.")
    }
}

impl<S: StateReader> StateReader for VersionedStateProxy<S> {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        let mut state = self.state();
        match state.storage.read(self.tx_index, (contract_address, key)) {
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
        match state.nonces.read(self.tx_index, contract_address) {
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
        match state.class_hashes.read(self.tx_index, contract_address) {
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
        match state.compiled_class_hashes.read(self.tx_index, class_hash) {
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
        match state.compiled_contract_classes.read(self.tx_index, class_hash) {
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
