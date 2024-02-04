use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::concurrency::versioned_storage::{Version, VersionedStorage};
use crate::execution::contract_class::ContractClass;
use crate::state::state_api::{StateReader, StateResult};

#[cfg(test)]
#[path = "versioned_state_test.rs"]
pub mod test;

/// A collection of versioned storages.
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
            storage: VersionedStorage::new(),
            nonces: VersionedStorage::new(),
            class_hashes: VersionedStorage::new(),
            compiled_class_hashes: VersionedStorage::new(),
            compiled_contract_classes: VersionedStorage::new(),
        }
    }

    // Reads
    pub fn get_storage_at(
        &mut self,
        version: Version,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        let value = self.storage.read(version, (contract_address, key)).unwrap_or({
            let initial_value = self.initial_state.get_storage_at(contract_address, key)?;
            self.storage.set_initial_value((contract_address, key), initial_value);
            initial_value
        });

        Ok(value)
    }

    pub fn get_nonce_at(
        &mut self,
        version: Version,
        contract_address: ContractAddress,
    ) -> StateResult<Nonce> {
        let value = self.nonces.read(version, contract_address).unwrap_or({
            let initial_value = self.initial_state.get_nonce_at(contract_address)?;
            self.nonces.set_initial_value(contract_address, initial_value);
            initial_value
        });

        Ok(value)
    }

    pub fn get_class_hash_at(
        &mut self,
        version: Version,
        contract_address: ContractAddress,
    ) -> StateResult<ClassHash> {
        let value = self.class_hashes.read(version, contract_address).unwrap_or({
            let initial_value = self.initial_state.get_class_hash_at(contract_address)?;
            self.class_hashes.set_initial_value(contract_address, initial_value);
            initial_value
        });

        Ok(value)
    }

    pub fn get_compiled_class_hash(
        &mut self,
        version: Version,
        class_hash: ClassHash,
    ) -> StateResult<CompiledClassHash> {
        let value = self.compiled_class_hashes.read(version, class_hash).unwrap_or({
            let initial_value = self.initial_state.get_compiled_class_hash(class_hash)?;
            self.compiled_class_hashes.set_initial_value(class_hash, initial_value);
            initial_value
        });

        Ok(value)
    }

    pub fn get_compiled_contract_class(
        &mut self,
        version: Version,
        class_hash: ClassHash,
    ) -> StateResult<ContractClass> {
        let value = self.compiled_contract_classes.read(version, class_hash).unwrap_or({
            let initial_value = self.initial_state.get_compiled_contract_class(class_hash)?;
            self.compiled_contract_classes.set_initial_value(class_hash, initial_value.clone());
            initial_value
        });

        Ok(value)
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
