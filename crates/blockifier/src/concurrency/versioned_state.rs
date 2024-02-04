use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::concurrency::versioned_storage::VersionedStorage;
use crate::concurrency::Version;
use crate::execution::contract_class::ContractClass;
use crate::state::state_api::{StateReader, StateResult};

#[cfg(test)]
#[path = "versioned_state_test.rs"]
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

    // Reads
    pub fn get_storage_at(
        &mut self,
        version: Version,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        match self.storage.read(version, (contract_address, key)) {
            Some(value) => Ok(value),
            None => {
                let initial_value = self.initial_state.get_storage_at(contract_address, key)?;
                self.storage.set_initial_value((contract_address, key), initial_value);
                Ok(initial_value)
            }
        }
    }

    pub fn get_nonce_at(
        &mut self,
        version: Version,
        contract_address: ContractAddress,
    ) -> StateResult<Nonce> {
        match self.nonces.read(version, contract_address) {
            Some(value) => Ok(value),
            None => {
                let initial_value = self.initial_state.get_nonce_at(contract_address)?;
                self.nonces.set_initial_value(contract_address, initial_value);
                Ok(initial_value)
            }
        }
    }

    pub fn get_class_hash_at(
        &mut self,
        version: Version,
        contract_address: ContractAddress,
    ) -> StateResult<ClassHash> {
        match self.class_hashes.read(version, contract_address) {
            Some(value) => Ok(value),
            None => {
                let initial_value = self.initial_state.get_class_hash_at(contract_address)?;
                self.class_hashes.set_initial_value(contract_address, initial_value);
                Ok(initial_value)
            }
        }
    }

    pub fn get_compiled_class_hash(
        &mut self,
        version: Version,
        class_hash: ClassHash,
    ) -> StateResult<CompiledClassHash> {
        match self.compiled_class_hashes.read(version, class_hash) {
            Some(value) => Ok(value),
            None => {
                let initial_value = self.initial_state.get_compiled_class_hash(class_hash)?;
                self.compiled_class_hashes.set_initial_value(class_hash, initial_value);
                Ok(initial_value)
            }
        }
    }

    pub fn get_compiled_contract_class(
        &mut self,
        version: Version,
        class_hash: ClassHash,
    ) -> StateResult<ContractClass> {
        match self.compiled_contract_classes.read(version, class_hash) {
            Some(value) => Ok(value),
            None => {
                let initial_value = self.initial_state.get_compiled_contract_class(class_hash)?;
                self.compiled_contract_classes.set_initial_value(class_hash, initial_value.clone());
                Ok(initial_value)
            }
        }
    }

    // Writes
    pub fn set_storage_at(
        &mut self,
        version: Version,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) {
        self.storage.write(version, (contract_address, key), value);
    }

    pub fn set_class_hash_at(
        &mut self,
        version: Version,
        contract_address: ContractAddress,
        class_hash: ClassHash,
    ) {
        self.class_hashes.write(version, contract_address, class_hash);
    }

    pub fn set_nonce_at(
        &mut self,
        version: Version,
        contract_address: ContractAddress,
        nonce: Nonce,
    ) {
        self.nonces.write(version, contract_address, nonce);
    }

    pub fn set_compiled_class_hash(
        &mut self,
        version: Version,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
    ) {
        self.compiled_class_hashes.write(version, class_hash, compiled_class_hash);
    }

    pub fn set_compiled_contract_class(
        &mut self,
        version: Version,
        class_hash: ClassHash,
        contract_class: ContractClass,
    ) {
        self.compiled_contract_classes.write(version, class_hash, contract_class);
    }
}
