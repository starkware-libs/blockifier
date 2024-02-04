use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::concurrency::versioned_storage::{Version, VersionedStorage};
use crate::execution::contract_class::ContractClass;
use crate::state::state_api::{StateReader, StateResult};

#[cfg(test)]
#[path = "versioned_state_test.rs"]
pub mod test;

///    A collection of versioned storages.
pub struct VersionedState<S: StateReader> {
    initial_state: S,
    storage_writes: VersionedStorage<(ContractAddress, StorageKey), StarkFelt>,
    nonce_writes: VersionedStorage<ContractAddress, Nonce>,
    class_hash_writes: VersionedStorage<ContractAddress, ClassHash>,
    compiled_class_hash_writes: VersionedStorage<ClassHash, CompiledClassHash>,
    compiled_contract_class_writes: VersionedStorage<ClassHash, ContractClass>,
}

impl<S: StateReader> VersionedState<S> {
    pub fn new(initial_state: S) -> Self {
        VersionedState {
            initial_state,
            storage_writes: VersionedStorage::new(),
            nonce_writes: VersionedStorage::new(),
            class_hash_writes: VersionedStorage::new(),
            compiled_class_hash_writes: VersionedStorage::new(),
            compiled_contract_class_writes: VersionedStorage::new(),
        }
    }

    // Reads
    pub fn get_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        version: Version,
    ) -> StateResult<StarkFelt> {
        if self.storage_writes.read((contract_address, key), version).is_none() {
            let storage_value = self.initial_state.get_storage_at(contract_address, key)?;
            self.storage_writes.set_initial_value((contract_address, key), storage_value);
        }

        Ok(self.storage_writes.read((contract_address, key), version).unwrap())
    }

    pub fn get_nonce_at(
        &mut self,
        contract_address: ContractAddress,
        version: Version,
    ) -> StateResult<Nonce> {
        if self.nonce_writes.read(contract_address, version).is_none() {
            let nonce_value = self.initial_state.get_nonce_at(contract_address)?;
            self.nonce_writes.set_initial_value(contract_address, nonce_value);
        }

        Ok(self.nonce_writes.read(contract_address, version).unwrap())
    }

    pub fn get_class_hash_at(
        &mut self,
        contract_address: ContractAddress,
        version: Version,
    ) -> StateResult<ClassHash> {
        if self.class_hash_writes.read(contract_address, version).is_none() {
            let class_hash_value = self.initial_state.get_class_hash_at(contract_address)?;
            self.class_hash_writes.set_initial_value(contract_address, class_hash_value);
        }

        Ok(self.class_hash_writes.read(contract_address, version).unwrap())
    }

    pub fn get_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
        version: Version,
    ) -> StateResult<CompiledClassHash> {
        if self.compiled_class_hash_writes.read(class_hash, version).is_none() {
            let compiled_class_hash_value =
                self.initial_state.get_compiled_class_hash(class_hash)?;
            self.compiled_class_hash_writes
                .set_initial_value(class_hash, compiled_class_hash_value);
        }

        Ok(self.compiled_class_hash_writes.read(class_hash, version).unwrap())
    }

    pub fn get_compiled_contract_class(
        &mut self,
        class_hash: ClassHash,
        version: Version,
    ) -> StateResult<ContractClass> {
        if self.compiled_contract_class_writes.read(class_hash, version).is_none() {
            let compiled_contract_class_value =
                self.initial_state.get_compiled_contract_class(class_hash)?;
            self.compiled_contract_class_writes
                .set_initial_value(class_hash, compiled_contract_class_value);
        }

        Ok(self.compiled_contract_class_writes.read(class_hash, version).unwrap())
    }

    // Writes
    pub fn set_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
        version: Version,
    ) {
        self.storage_writes.write((contract_address, key), version, value);
    }

    pub fn set_class_hash_at(
        &mut self,
        contract_address: ContractAddress,
        class_hash: ClassHash,
        version: Version,
    ) {
        self.class_hash_writes.write(contract_address, version, class_hash);
    }

    pub fn set_nonce_at(
        &mut self,
        contract_address: ContractAddress,
        nonce: Nonce,
        version: Version,
    ) {
        self.nonce_writes.write(contract_address, version, nonce);
    }

    pub fn set_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
        version: Version,
    ) {
        self.compiled_class_hash_writes.write(class_hash, version, compiled_class_hash);
    }

    pub fn set_compiled_contract_class(
        &mut self,
        class_hash: ClassHash,
        contract_class: ContractClass,
        version: Version,
    ) {
        self.compiled_contract_class_writes.write(class_hash, version, contract_class);
    }
}
