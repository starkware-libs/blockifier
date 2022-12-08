use std::collections::HashMap;

use anyhow::{Context, Result};
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

#[cfg(test)]
#[path = "cached_state_test.rs"]
mod test;

/// Caches read and write requests.
///
/// Writer functionality is built-in, whereas Reader functionality is injected through
/// initialization.
#[derive(Default)]
pub struct CachedState<SR: StateReader> {
    pub state_reader: SR,
    // Invariant: the cache should remain private.
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
            self.cache.set_storage_initial_value(contract_address, key, storage_value);
        }

        self.cache.get_storage_at(contract_address, key).with_context(|| {
            format!("Cannot retrieve '{contract_address:?}' and '{key:?}' from the cache.")
        })
    }

    pub fn set_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) {
        self.cache.set_storage_value(contract_address, key, value);
    }

    pub fn get_nonce_at(&mut self, contract_address: ContractAddress) -> Result<&Nonce> {
        if self.cache.get_nonce_at(contract_address).is_none() {
            let nonce = self.state_reader.get_nonce_at(contract_address)?;
            self.cache.set_nonce_initial_value(contract_address, nonce);
        }

        self.cache
            .get_nonce_at(contract_address)
            .with_context(|| format!("Cannot retrieve '{contract_address:?}' from the cache."))
    }

    // TODO(Gilad, 1/12/22) consider moving some this logic into starknet-api; Nonce should
    // be able to increment itself.
    pub fn increment_nonce(&mut self, contract_address: ContractAddress) -> Result<()> {
        let current_nonce = *self.get_nonce_at(contract_address)?;
        let next_nonce = u64_try_from_starkfelt(current_nonce.0)? + 1_u64;
        let next_nonce = nonce_try_from_u64(next_nonce)?;
        self.cache.set_nonce_value(contract_address, next_nonce);
        Ok(())
    }
}

/// A read-only API for accessing StarkNet global state.
pub trait StateReader {
    /// Returns the storage value under the given key in the given contract instance (represented by
    /// its address).
    /// Default: 0 for an uninitialized contract address.
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> Result<StarkFelt>;

    /// Returns the nonce of the given contract instance.
    /// Default: 0 for an uninitialized contract address.
    fn get_nonce_at(&self, contract_address: ContractAddress) -> Result<Nonce>;

    /// Returns the class hash of the contract class at the given contract instance.
    /// Default: 0 (uninitialized class hash) for an uninitialized contract address.
    fn get_class_hash_at(&self, _contract_address: ContractAddress) -> Result<ClassHash> {
        unimplemented!();
    }
}

type ContractStorageKey = (ContractAddress, StorageKey);

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
    ) -> Result<StarkFelt> {
        let contract_storage_key = (contract_address, key);
        let value = self
            .contract_storage_key_to_value
            .get(&contract_storage_key)
            .copied()
            .unwrap_or_default();
        Ok(value)
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> Result<Nonce> {
        let nonce =
            self.contract_address_to_nonce.get(&contract_address).copied().unwrap_or_default();
        Ok(nonce)
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

    pub fn set_storage_initial_value(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) {
        let contract_storage_key = (contract_address, key);
        self.storage_initial_values.insert(contract_storage_key, value);
    }

    fn set_storage_value(
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

    fn set_nonce_initial_value(&mut self, contract_address: ContractAddress, nonce: Nonce) {
        self.nonce_initial_values.insert(contract_address, nonce);
    }

    fn set_nonce_value(&mut self, contract_address: ContractAddress, nonce: Nonce) {
        self.nonce_writes.insert(contract_address, nonce);
    }
}

// TODO(Gilad, 1/12/2022): Move this to Starknet_api and convert to `TryFrom`
// Also, check why are we using u64 and not BigInt (we are losing information in the cast).
fn u64_try_from_starkfelt(hash: StarkFelt) -> Result<u64> {
    let as_bytes: [u8; 8] = hash.bytes()[24..32].try_into()?;
    Ok(u64::from_be_bytes(as_bytes))
}

// TODO(Gilad, 1/12/2022): Move this to Starknet_api and convert to `From`
fn nonce_try_from_u64(num: u64) -> Result<Nonce> {
    let num_hex = format!("0x{num:x}");
    let felt = StarkFelt::try_from(num_hex.as_str())?;
    Ok(Nonce(felt))
}
