use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use super::versioned_storage::{Version, VersionedStorage};
use crate::state::cached_state::CachedState;
use crate::state::errors::StateError;
use crate::state::state_api::{StateReader, StateResult};
use crate::test_utils::dict_state_reader::DictStateReader;

#[cfg(test)]
#[path = "versioned_state_test.rs"]
pub mod test;

pub struct VersionedCacheState {
    nonce_writes: VersionedStorage<ContractAddress, Nonce>,
    class_hash_writes: VersionedStorage<ContractAddress, ClassHash>,
    storage_writes: VersionedStorage<(ContractAddress, StorageKey), StarkFelt>,
    compiled_class_hash_writes: VersionedStorage<ClassHash, CompiledClassHash>,
}

impl VersionedCacheState {
    pub fn new(state: &'static CachedState<DictStateReader>) -> Self {
        // Initiate the hashmap (versioned_storage) with the functions from state

        let get_nonce = |address: ContractAddress| -> StateResult<Nonce> {
            state.get_nonce_initial_value(address)
        };

        let get_compiled_class_hash = |class_hash: ClassHash| -> StateResult<CompiledClassHash> {
            state.get_compiled_class_hash_initial_value(class_hash)
        };
        let get_class_hash = |address: ContractAddress| -> StateResult<ClassHash> {
            state.get_class_hash_initial_value(address)
        };
        let get_storage =
            |address_key_pair: (ContractAddress, StorageKey)| -> StateResult<StarkFelt> {
                state.get_storage_initial_value(address_key_pair.0, address_key_pair.1)
            };

        let contract_storage_versioned_storage = VersionedStorage::new(Box::new(get_storage));
        let class_hash_versioned_storage = VersionedStorage::new(Box::new(get_class_hash));
        let nonce_versioned_storage = VersionedStorage::new(Box::new(get_nonce));
        let compiled_class_hash_versioned_storage =
            VersionedStorage::new(Box::new(get_compiled_class_hash));

        VersionedCacheState {
            nonce_writes: nonce_versioned_storage,
            class_hash_writes: class_hash_versioned_storage,
            storage_writes: contract_storage_versioned_storage,
            compiled_class_hash_writes: compiled_class_hash_versioned_storage,
        }
    }

    // Reads
    pub fn get_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        version: Version,
    ) -> StateResult<StarkFelt> {
        Ok(self.storage_writes.read((contract_address, key), version))
    }

    pub fn get_nonce_at(
        &mut self,
        contract_address: ContractAddress,
        version: Version,
    ) -> StateResult<Nonce> {
        Ok(self.nonce_writes.read(contract_address, version))
    }

    pub fn get_class_hash_at(
        &mut self,
        contract_address: ContractAddress,
        version: Version,
    ) -> StateResult<ClassHash> {
        Ok(self.class_hash_writes.read(contract_address, version))
    }

    pub fn get_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
        version: Version,
    ) -> StateResult<CompiledClassHash> {
        Ok(self.compiled_class_hash_writes.read(class_hash, version))
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

    pub fn set_nonce(
        &mut self,
        contract_address: ContractAddress,
        nonce: Nonce,
        version: Version,
    ) -> StateResult<()> {
        self.nonce_writes.write(contract_address, version, nonce);

        Ok(())
    }

    pub fn set_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
        version: Version,
    ) -> StateResult<()> {
        self.compiled_class_hash_writes.write(class_hash, version, compiled_class_hash);

        Ok(())
    }
}
