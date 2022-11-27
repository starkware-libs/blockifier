use std::collections::HashMap;

// TODO(Gilad, 1/12/2022) remove anyhow from this file and use thiserror.
use anyhow::{ensure, Context, Result};
use starknet_api::{ClassHash, ContractAddress, Nonce, StarkFelt, StorageKey};

#[cfg(test)]
#[path = "cached_state_test.rs"]
mod test;

/// Holds read and write requests.
///
/// Writer functionality is built-in, whereas Reader functionality is injected through
/// initialization.
pub struct CachedState<SR: StateReader> {
    pub state_reader: SR,
    // Invariant: StateCache is a private type.
    cache: StateCache,
}

impl<SR: StateReader> CachedState<SR> {
    pub fn new(state_reader: SR) -> Self {
        Self { state_reader, cache: StateCache::default() }
    }

    pub fn get_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> Result<&StarkFelt> {
        if self.cache.get_storage_at(contract_address, key).is_none() {
            let storage_value = self.state_reader.get_storage_at(contract_address, key)?;
            self.cache.try_insert_storage_initial_value(&contract_address, &key, *storage_value)?;
        }

        self.cache
            .get_storage_at(contract_address, key)
            .with_context(|| format!("Cannot retrieve '{contract_address:?}' from the cache."))
    }

    pub fn set_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) {
        self.cache.set_storage_writes(contract_address, key, value);
    }

    pub fn get_nonce_at(&mut self, contract_address: ContractAddress) -> Result<&Nonce> {
        if self.cache.get_storage_at(contract_address, key).is_none() {
            let storage_value = self.state_reader.get_storage_at(contract_address, key)?;
            self.cache.try_insert_storage_initial_value(&contract_address, &key, *storage_value)?;
        }

        self.cache
            .get_storage_at(contract_address, key)
            .with_context(|| format!("Cannot retrieve '{contract_address:?}' from the cache."))
    }
}

/// A read-only API for accessing StarkNet global state.
pub trait StateReader {
    /// Returns the storage value under the given key in the given contract instance.
    fn get_storage_at(
        &self,
        _contract_address: ContractAddress,
        _key: StorageKey,
    ) -> Result<&StarkFelt> {
        unimplemented!();
    }

    /// Returns the nonce of the given contract instance (represented by its address).
    fn get_nonce_at(&self, _contract_address: ContractAddress) -> Result<&Nonce>;

    /// Returns the class hash of the contract class at the given address.
    fn get_class_hash_at(&self, _contract_address: ContractAddress) -> Result<&ClassHash> {
        unimplemented!();
    }
}

type ContractStorageKey = (ContractAddress, StorageKey);

pub struct DictStateReader {
    pub contract_storage_key_to_felt: HashMap<ContractStorageKey, StarkFelt>,
}

impl StateReader for DictStateReader {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> Result<&StarkFelt> {
        let contract_storage_key = (contract_address, key);
        self.contract_storage_key_to_felt
            .get(&contract_storage_key)
            .with_context(|| format!("{contract_address:?} should have a nonce."))
    }
}

/// Holds read and write requests.
// Invariant: cannot delete keys from fields.
#[derive(Default)]
struct StateCache {
    // Reader's cached information; initial values, read before any write operation (per cell).
    nonce_initial_values: HashMap<ContractAddress, Nonce>,
    _class_hash_initial_values: HashMap<ContractAddress, ClassHash>,
    storage_initial_values: HashMap<ContractStorageKey, StarkFelt>,

    // Writer's cached information.
    nonce_writes: HashMap<ContractAddress, Nonce>,
    _class_hash_writes: HashMap<ContractAddress, ClassHash>,
    storage_writes: HashMap<ContractStorageKey, StarkFelt>,
}

impl StateCache {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> Option<&StarkFelt> {
        let contract_storage_key = (contract_address, key);
        self.storage_writes
            .get(&contract_storage_key)
            .or_else(|| self.storage_initial_values.get(&contract_storage_key))
    }

    pub fn try_insert_storage_initial_value(
        &mut self,
        contract_address: &ContractAddress,
        key: &StorageKey,
        value: StarkFelt,
    ) -> Result<()> {
        let contract_storage_key = (*contract_address, *key);
        ensure!(
            !self.storage_initial_values.contains_key(&contract_storage_key),
            "{contract_address:?} already has initial value {:?}",
            self.storage_initial_values.get(&contract_storage_key)
        );
        self.storage_initial_values.insert(contract_storage_key, value);
        Ok(())
    }

    fn set_storage_writes(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) {
        let contract_storage_key = (contract_address, key);
        self.storage_writes.insert(contract_storage_key, value);
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> Option<&Nonce> {
        self.storage_writes
            .get(&contract_address)
            .or_else(|| self.nonce_initial_values.get(&contract_address))
    }

    pub fn try_insert_nonce_initial_value(
        &mut self,
        contract_address: &ContractAddress,
        nonce: Nonce,
    ) -> Result<()> {
        ensure!(
            !self.nonce_initial_values.contains_key(&contract_address),
            "{contract_address:?} already has initial value {:?}",
            self.nonce_initial_values.get(&contract_address)
        );
        self.nonce_initial_values.insert(contract_address, nonce);
        Ok(())
    }

    fn set_storage_writes(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) {
        let contract_storage_key = (contract_address, key);
        self.storage_writes.insert(contract_storage_key, value);
    }
}
