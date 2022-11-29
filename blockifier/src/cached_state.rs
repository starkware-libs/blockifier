use std::collections::HashMap;
use std::fmt::Debug;

use anyhow::{Context, Result};
use starknet_api::{ClassHash, ContractAddress, Nonce, StarkFelt, StorageKey};

#[cfg(test)]
#[path = "cached_state_test.rs"]
mod test;

/// Caches read and write requests.
///
/// Writer functionality is built-in, whereas Reader functionality is injected through
/// initialization.
pub struct CachedState<SR: StateReader> {
    pub state_reader: SR,
    // Invariant: The cache maintains private types.
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
            self.cache.set_storage_initial_values(contract_address, key, *storage_value);
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

    // TODO(Gilad, 1/12/22) consider moving some of this logic into starknet-api, Nonce should
    // be able to increment itself.
    pub fn increment_nonce(&mut self, contract_address: ContractAddress) -> Result<()> {
        let current_nonce = self.get_nonce_at(contract_address)?.nonce();
        let incremented_nonce_val = u64_try_from_starkfelt(current_nonce)? + 1_u64;

        let incremented_nonce = nonce_try_from_u64(incremented_nonce_val)?;
        self.cache.set_nonce_writes(contract_address, incremented_nonce);
        Ok(())
    }

    pub fn get_nonce_at(&mut self, contract_address: ContractAddress) -> Result<&Nonce> {
        if self.cache.get_nonce_at(contract_address).is_none() {
            let nonce = self.state_reader.get_nonce_at(contract_address)?;
            self.cache.set_nonce_initial_values(contract_address, *nonce);
        }

        self.cache
            .get_nonce_at(contract_address)
            .with_context(|| format!("Cannot retrieve '{contract_address:?}' from the cache."))
    }
}

/// A read-only API for accessing StarkNet global state.
pub trait StateReader {
    /// Returns the storage value under the given key in the given contract instance (represented by
    /// its address).
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> Result<&StarkFelt>;

    /// Returns the nonce of the given contract instance.
    fn get_nonce_at(&self, contract_address: ContractAddress) -> Result<&Nonce>;

    /// Returns the class hash of the contract class at the given contract instance.
    fn get_class_hash_at(&self, _contract_address: ContractAddress) -> Result<&ClassHash> {
        unimplemented!();
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[error("Failed to fetch {key} from current state.")]
pub struct StateReaderError {
    key: String,
}

impl From<ContractAddress> for StateReaderError {
    fn from(key: ContractAddress) -> Self {
        Self { key: format!("{key:?}") }
    }
}
impl From<ContractStorageKey> for StateReaderError {
    fn from(key: ContractStorageKey) -> Self {
        Self { key: format!("{key:?}") }
    }
}

pub type ContractStorageKey = (ContractAddress, StorageKey);

/// A simple implementation of `StateReader` using `HashMap`s for storage.
#[derive(Default)]
pub struct DictStateReader {
    pub contract_storage_key_to_value: HashMap<ContractStorageKey, StarkFelt>,
    pub contract_address_to_nonce: HashMap<ContractAddress, Nonce>,
}

impl StateReader for DictStateReader {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> Result<&StarkFelt> {
        let contract_storage_key = (contract_address, key);
        self.contract_storage_key_to_value
            .get(&contract_storage_key)
            .with_context(|| format!("{contract_address:?} should have storage."))
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> Result<&Nonce> {
        self.contract_address_to_nonce
            .get(&contract_address)
            .with_context(|| format!("{contract_address:?} should have a nonce."))
    }
}

/// Caches read and write requests.
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

    pub fn set_storage_initial_values(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) {
        let contract_storage_key = (contract_address, key);
        self.storage_initial_values.insert(contract_storage_key, value);
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
        self.nonce_writes
            .get(&contract_address)
            .or_else(|| self.nonce_initial_values.get(&contract_address))
    }

    fn set_nonce_initial_values(&mut self, contract_address: ContractAddress, nonce: Nonce) {
        self.nonce_initial_values.insert(contract_address, nonce);
    }

    fn set_nonce_writes(&mut self, contract_address: ContractAddress, nonce: Nonce) {
        self.nonce_writes.insert(contract_address, nonce);
    }
}

// TODO(Gilad, 1/12/2022): Move this to Starknet_api and convert to `TryFrom`
fn u64_try_from_starkfelt(hash: &StarkFelt) -> Result<u64> {
    let as_bytes: [u8; 8] = hash.bytes()[24..32].try_into()?;
    Ok(u64::from_be_bytes(as_bytes))
}

// TODO(Gilad, 1/12/2022): Move this to Starknet_api and convert to `From`
fn nonce_try_from_u64(num: u64) -> Result<Nonce> {
    let num_hex = format!("0x{num:x}");
    let felt = StarkFelt::from_hex(&num_hex)?;
    Ok(Nonce::new(felt))
}
