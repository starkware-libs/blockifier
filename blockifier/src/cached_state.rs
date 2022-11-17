#[cfg(test)]
pub mod cached_state_test;

use std::collections::HashMap;

// TODO(Gilad, 1/12/2022) remove anyhow from this file and use thiserror.
use anyhow::{ensure, Context, Result};
use starknet_api::{ClassHash, ContractAddress, Nonce, StarkFelt, StorageEntry, StorageKey};

/// A read-only API for accessing StarkNet global state.
pub trait StateReader {
    /// Returns the nonce of the given contract instance.
    fn get_nonce_at(&self, contract_address: ContractAddress) -> Result<&Nonce>;

    /// Returns the class hash of the contract class at the given address.
    fn get_class_hash_at(&self, _contract_address: ContractAddress) -> Result<&ClassHash> {
        unimplemented!();
    }

    /// Returns the storage value under the given key in the given contract instance.
    fn get_storage_at(
        &self,
        _contract_address: ContractAddress,
        _key: StorageKey,
    ) -> Result<&StorageEntry> {
        unimplemented!();
    }
}

pub struct DictStateReader {
    pub contract_address_to_nonce: HashMap<ContractAddress, Nonce>,
}

impl StateReader for DictStateReader {
    fn get_nonce_at(&self, contract_address: ContractAddress) -> Result<&Nonce> {
        self.contract_address_to_nonce
            .get(&contract_address)
            .with_context(|| format!("{:?} should have a nonce.", contract_address))
    }
}

/// Holds read and write requests.
///
/// Writer functionality is built-in, whereas Reader functionality is injected through
/// initialization.
pub struct CachedState<SR: StateReader> {
    pub state_reader: SR,
    // Invariant: StateCache is a private type.
    _cache: StateCache,
}

impl<SR: StateReader> CachedState<SR> {
    pub fn new(state_reader: SR) -> Self {
        Self { state_reader, _cache: StateCache::default() }
    }

    pub fn increment_nonce(&mut self, contract_address: ContractAddress) -> Result<()> {
        let current_nonce = self.get_nonce_at(contract_address)?;
        let incremented_nonce = u64_try_from_starkfelt(&current_nonce.0)? + 1_u64;

        *current_nonce = nonce_from_u64(incremented_nonce);
        Ok(())
    }

    pub fn get_nonce_at(&mut self, contract_address: ContractAddress) -> Result<&mut Nonce> {
        if self._cache.get_nonce(contract_address).is_none() {
            let nonce = self.state_reader.get_nonce_at(contract_address)?;
            self._cache.try_insert_nonce_initial_value(&contract_address, *nonce)?;
        }

        self._cache.get_nonce(contract_address).ok_or_else(|| {
            panic!("Cannot retrieve contract address '{:?}' from the cache.", contract_address)
        })
    }
}

// TODO(Gilad, 1/12/2022): Move this to Starknet_api and convert to `TryFrom`
pub fn u64_try_from_starkfelt(hash: &StarkFelt) -> Result<u64> {
    let as_bytes: [u8; 8] = hash.bytes()[24..32].try_into()?;
    Ok(u64::from_be_bytes(as_bytes))
}

// TODO(Gilad, 1/12/2022): Move this to Starknet_api and convert to `From`
pub fn nonce_from_u64(num: u64) -> Nonce {
    Nonce(StarkFelt::from(num))
}

/// Holds read and write requests.
// Invariant: can't delete keys from fields.
#[derive(Default)]
struct StateCache {
    _nonce_initial_values: HashMap<ContractAddress, Nonce>,
    _nonce_writes: HashMap<ContractAddress, Nonce>,
}

impl StateCache {
    pub fn try_insert_nonce_initial_value(
        &mut self,
        contract_address: &ContractAddress,
        nonce: Nonce,
    ) -> Result<()> {
        ensure!(
            !self._nonce_initial_values.contains_key(contract_address),
            "contract_address {:?} already has initial nonce {:?}",
            contract_address,
            self._nonce_initial_values.get(contract_address)
        );
        self._nonce_initial_values.insert(*contract_address, nonce);
        Ok(())
    }

    /// Looks for the contract address key in the writes cache, then in the initial values.
    fn get_nonce(&mut self, contract_address: ContractAddress) -> Option<&mut Nonce> {
        self._nonce_writes
            .get_mut(&contract_address)
            .or_else(|| self._nonce_initial_values.get_mut(&contract_address))
    }
}
