use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard};

use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::concurrency::versioned_storage::VersionedStorage;
use crate::concurrency::TxIndex;
use crate::execution::contract_class::ContractClass;
use crate::state::cached_state::{ContractClassMapping, StateCache};
use crate::state::state_api::{State, StateReader, StateResult};

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

    // Note: Invoke this function after `update_initial_values_of_write_only_access`.
    // Transactions that overwrite previously written values are not charged. Hence, altering a
    // write-only cell can impact the fee calculation, leading to a re-execution.
    // TODO(Mohammad, 01/04/2024): Store the read set (and write set) within a shared
    // object (probabily `VersionedState`). As RefCell operations are not thread-safe. Therefore,
    // accessing this function should be protected by a mutex to ensure thread safety.
    pub fn validate_read_set(&mut self, tx_index: TxIndex, state_cache: &mut StateCache) -> bool {
        // If is the first transaction in the chunk, then the read set is valid. Since it has no
        // predecessors, there's nothing to compare it to.
        if tx_index == 0 {
            return true;
        }
        for (&(contract_address, storage_key), expected_value) in
            &state_cache.storage_initial_values
        {
            let value =
                self.storage.read(tx_index, (contract_address, storage_key)).expect(READ_ERR);

            if &value != expected_value {
                return false;
            }
        }

        for (&contract_address, expected_value) in &state_cache.nonce_initial_values {
            let value = self.nonces.read(tx_index, contract_address).expect(READ_ERR);

            if &value != expected_value {
                return false;
            }
        }

        for (&contract_address, expected_value) in &state_cache.class_hash_initial_values {
            let value = self.class_hashes.read(tx_index, contract_address).expect(READ_ERR);

            if &value != expected_value {
                return false;
            }
        }

        // Added for symmetry. We currently do not update this initial mapping.
        for (&class_hash, expected_value) in &state_cache.compiled_class_hash_initial_values {
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
        state_cache: &mut StateCache,
        class_hash_to_class: ContractClassMapping,
    ) {
        for (&key, &value) in &state_cache.storage_writes {
            self.storage.write(tx_index, key, value);
        }
        for (&key, &value) in &state_cache.nonce_writes {
            self.nonces.write(tx_index, key, value);
        }
        for (&key, &value) in &state_cache.class_hash_writes {
            self.class_hashes.write(tx_index, key, value);
        }
        for (&key, &value) in &state_cache.compiled_class_hash_writes {
            self.compiled_class_hashes.write(tx_index, key, value);
        }
        for (key, value) in class_hash_to_class {
            self.compiled_contract_classes.write(tx_index, key, value.clone());
        }
    }
}

pub struct ThreadSafeVersionedState<S: StateReader>(Arc<Mutex<VersionedState<S>>>);

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
    fn state(&self) -> MutexGuard<'_, VersionedState<S>> {
        self.state.lock().expect("Failed to acquire state lock.")
    }
}

// TODO: Remove.
impl<S: StateReader> State for VersionedStateProxy<S> {
    fn set_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) -> StateResult<()> {
        let mut state = self.state();
        state.storage.write(self.tx_index, (contract_address, key), value);

        Ok(())
    }

    fn set_class_hash_at(
        &mut self,
        contract_address: ContractAddress,
        class_hash: ClassHash,
    ) -> StateResult<()> {
        let mut state = self.state();
        state.class_hashes.write(self.tx_index, contract_address, class_hash);

        Ok(())
    }

    fn increment_nonce(&mut self, contract_address: ContractAddress) -> StateResult<()> {
        let mut state = self.state();
        let current_nonce = state.nonces.read(self.tx_index, contract_address).unwrap();

        let current_nonce_as_u64: u64 =
            usize::try_from(current_nonce.0)?.try_into().expect("Failed to convert usize to u64.");
        let next_nonce_val = 1_u64 + current_nonce_as_u64;
        let next_nonce = Nonce(StarkFelt::from(next_nonce_val));
        state.nonces.write(self.tx_index, contract_address, next_nonce);

        Ok(())
    }

    fn set_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
    ) -> StateResult<()> {
        let mut state = self.state();
        state.compiled_class_hashes.write(self.tx_index, class_hash, compiled_class_hash);

        Ok(())
    }

    fn set_contract_class(
        &mut self,
        class_hash: ClassHash,
        contract_class: ContractClass,
    ) -> StateResult<()> {
        let mut state = self.state();
        state.compiled_contract_classes.write(self.tx_index, class_hash, contract_class);

        Ok(())
    }

    fn add_visited_pcs(&mut self, _class_hash: ClassHash, _pcs: &HashSet<usize>) {
        todo!()
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

    fn is_declared(&self, class_hash: ClassHash) -> bool {
        self.get_compiled_contract_class(class_hash).is_ok()
    }
}
