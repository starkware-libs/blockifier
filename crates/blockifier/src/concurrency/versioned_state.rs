use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use super::versioned_storage::{Version, VersionedStorage};
use crate::state::cached_state::CachedState;
use crate::state::errors::StateError;
use crate::state::state_api::{StateReader, StateResult};

#[cfg(test)]
#[path = "versioned_state_test.rs"]
pub mod test;

///    A collection of versioned storages.
pub struct VersionedState {
    nonce_writes: VersionedStorage<ContractAddress, Nonce>,
    class_hash_writes: VersionedStorage<ContractAddress, ClassHash>,
    storage_writes: VersionedStorage<(ContractAddress, StorageKey), StarkFelt>,
    compiled_class_hash_writes: VersionedStorage<ClassHash, CompiledClassHash>,
}

impl VersionedState {
    pub fn new(state: &'static CachedState<impl StateReader>) -> Self {
        // Initiate the hashmap (versioned_storage) with the functions from state

        let get_nonce = |address: ContractAddress| -> Option<Nonce> {
            match state.get_nonce_at(address) {
                Ok(nonce) => Some(nonce),
                Err(_) => None,
            }
        };

        let get_compiled_class_hash = |class_hash: ClassHash| -> Option<CompiledClassHash> {
            match state.get_compiled_class_hash(class_hash) {
                Ok(compiled_class_hash) => Some(compiled_class_hash),
                Err(_) => None,
            }
        };
        let get_class_hash = |address: ContractAddress| -> Option<ClassHash> {
            match state.get_class_hash_at(address) {
                Ok(class_hash) => Some(class_hash),
                Err(_) => None,
            }
        };
        let get_storage = |(contract_address, storage_address): (ContractAddress, StorageKey)| -> Option<StarkFelt> {
            match state.get_storage_at(contract_address, storage_address) {
                Ok(storage) => Some(storage),
                Err(_) => None,
            }
        };

        let contract_storage_versioned_storage = VersionedStorage::new(Box::new(get_storage));
        let class_hash_versioned_storage = VersionedStorage::new(Box::new(get_class_hash));
        let nonce_versioned_storage = VersionedStorage::new(Box::new(get_nonce));
        let compiled_class_hash_versioned_storage =
            VersionedStorage::new(Box::new(get_compiled_class_hash));

        VersionedState {
            nonce_writes: nonce_versioned_storage,
            class_hash_writes: class_hash_versioned_storage,
            storage_writes: contract_storage_versioned_storage,
            compiled_class_hash_writes: compiled_class_hash_versioned_storage,
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

    pub fn get_compiled_class_hash_at(
        &self,
        class_hash: ClassHash,
        version: Version,
    ) -> StateResult<CompiledClassHash> {
        self.compiled_class_hash_writes.read(class_hash, version)
    }

    // Writes
    pub fn set_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
        version: Version,
    ) -> StateResult<()> {
        self.storage_writes.write((contract_address, key), version, value);

        Ok(())
    }

    pub fn set_class_hash_at(
        &mut self,
        contract_address: ContractAddress,
        class_hash: ClassHash,
        version: Version,
    ) -> StateResult<()> {
        if contract_address == ContractAddress::default() {
            return Err(StateError::OutOfRangeContractAddress);
        }

        self.class_hash_writes.write(contract_address, version, class_hash);
        Ok(())
    }

    pub fn set_nonce_at(
        &mut self,
        contract_address: ContractAddress,
        nonce: Nonce,
        version: Version,
    ) -> StateResult<()> {
        self.nonce_writes.write(contract_address, version, nonce);

        Ok(())
    }

    pub fn set_compiled_class_hash_at(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
        version: Version,
    ) -> StateResult<()> {
        self.compiled_class_hash_writes.write(class_hash, version, compiled_class_hash);

        Ok(())
    }
}
