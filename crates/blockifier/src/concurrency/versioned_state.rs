use std::collections::HashMap;

use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use super::versioned_storage::{ReadCallback, Version, VersionedStorage};
use crate::execution::contract_class::ContractClass;
use crate::state::state_api::StateResult;

#[cfg(test)]
#[path = "versioned_state_test.rs"]
pub mod test;

///    A collection of versioned storages.
pub struct VersionedState {
    storage_writes: VersionedStorage<(ContractAddress, StorageKey), StarkFelt>,
    nonce_writes: VersionedStorage<ContractAddress, Nonce>,
    class_hash_writes: VersionedStorage<ContractAddress, ClassHash>,
    compiled_class_hash_writes: VersionedStorage<ClassHash, CompiledClassHash>,
    compiled_contract_class_writes: VersionedStorage<ClassHash, ContractClass>,
}

impl VersionedState {
    pub fn new(
        storage_view: HashMap<(ContractAddress, StorageKey), StarkFelt>,
        address_to_nonce: HashMap<ContractAddress, Nonce>,
        address_to_class_hash: HashMap<ContractAddress, ClassHash>,
        class_hash_to_class: HashMap<ClassHash, ContractClass>,
        class_hash_to_compiled_class_hash: HashMap<ClassHash, CompiledClassHash>,
    ) -> Self {
        // Create the read callbacks.
        let storage_view: Box<ReadCallback<(ContractAddress, StorageKey), StarkFelt>> = {
            let storage_view = storage_view.clone();
            Box::new(move |key| {
                storage_view.get(&key).cloned().map_or_else(|| Some(StarkFelt::default()), Some)
            })
        };
        let address_to_nonce_view: Box<ReadCallback<ContractAddress, Nonce>> = {
            let address_to_nonce = address_to_nonce.clone();
            Box::new(move |key| {
                address_to_nonce.get(&key).cloned().map_or_else(|| Some(Nonce::default()), Some)
            })
        };
        let address_to_class_hash_view: Box<ReadCallback<ContractAddress, ClassHash>> = {
            let address_to_class_hash = address_to_class_hash.clone();
            Box::new(move |key| {
                address_to_class_hash
                    .get(&key)
                    .cloned()
                    .map_or_else(|| Some(ClassHash::default()), Some)
            })
        };
        let class_hash_to_compiled_class_hash_view: Box<
            ReadCallback<ClassHash, CompiledClassHash>,
        > = {
            let class_hash_to_compiled_class_hash = class_hash_to_compiled_class_hash.clone();
            Box::new(move |key| {
                class_hash_to_compiled_class_hash.get(&key).cloned().map_or_else(|| None, Some)
            })
        };
        let class_hash_to_class_view: Box<ReadCallback<ClassHash, ContractClass>> = {
            let class_hash_to_class = class_hash_to_class.clone();
            Box::new(move |key| class_hash_to_class.get(&key).cloned().map_or_else(|| None, Some))
        };

        // Create the versioned storages.
        let contract_storage_versioned_storage = VersionedStorage::new(Box::new(storage_view));
        let nonce_versioned_storage = VersionedStorage::new(Box::new(address_to_nonce_view));
        let class_hash_versioned_storage =
            VersionedStorage::new(Box::new(address_to_class_hash_view));
        let compiled_class_hash_versioned_storage =
            VersionedStorage::new(Box::new(class_hash_to_compiled_class_hash_view));
        let compiled_contract_class_versioned_storage =
            VersionedStorage::new(Box::new(class_hash_to_class_view));

        VersionedState {
            storage_writes: contract_storage_versioned_storage,
            nonce_writes: nonce_versioned_storage,
            class_hash_writes: class_hash_versioned_storage,
            compiled_class_hash_writes: compiled_class_hash_versioned_storage,
            compiled_contract_class_writes: compiled_contract_class_versioned_storage,
        }
    }

    // Reads
    pub fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
        version: Version,
    ) -> StateResult<StarkFelt> {
        self.storage_writes.read((contract_address, key), version)
    }

    pub fn get_nonce_at(
        &self,
        contract_address: ContractAddress,
        version: Version,
    ) -> StateResult<Nonce> {
        self.nonce_writes.read(contract_address, version)
    }

    pub fn get_class_hash_at(
        &self,
        contract_address: ContractAddress,
        version: Version,
    ) -> StateResult<ClassHash> {
        self.class_hash_writes.read(contract_address, version)
    }

    pub fn get_compiled_class_hash(
        &self,
        class_hash: ClassHash,
        version: Version,
    ) -> StateResult<CompiledClassHash> {
        self.compiled_class_hash_writes.read(class_hash, version)
    }

    pub fn get_compiled_contract_class(
        &self,
        class_hash: ClassHash,
        version: Version,
    ) -> StateResult<ContractClass> {
        self.compiled_contract_class_writes.read(class_hash, version)
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
