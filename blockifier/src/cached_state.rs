use std::collections::HashMap;
use std::rc::Rc;

use anyhow::{Context, Result};
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::execution::contract_class::ContractClass;
use crate::state::errors::{StateError, StateReaderError};

#[cfg(test)]
#[path = "cached_state_test.rs"]
mod test;

pub type StateReaderResult<T> = Result<T, StateReaderError>;
pub type StateResult<T> = Result<T, StateError>;
type ContractClassMapping = HashMap<ClassHash, Rc<ContractClass>>;

/// Caches read and write requests.
///
/// Writer functionality is built-in, whereas Reader functionality is injected through
/// initialization.
#[derive(Default)]
pub struct CachedState<SR: StateReader> {
    pub state_reader: SR,
    // Invariant: following attributes should remain private.
    cache: StateCache,
    class_hash_to_class: ContractClassMapping,
}

impl<SR: StateReader> CachedState<SR> {
    pub fn new(state_reader: SR) -> Self {
        Self { state_reader, cache: StateCache::default(), class_hash_to_class: HashMap::default() }
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

    pub fn get_contract_class(
        &mut self,
        class_hash: &ClassHash,
    ) -> StateReaderResult<Rc<ContractClass>> {
        if !self.class_hash_to_class.contains_key(class_hash) {
            let contract_class = self.state_reader.get_contract_class(class_hash)?;
            self.class_hash_to_class.insert(*class_hash, Rc::clone(&contract_class));
        }

        Ok(Rc::clone(
            self.class_hash_to_class
                .get(class_hash)
                .expect("The class hash must appear in the cache."),
        ))
    }

    pub fn get_class_hash_at(
        &mut self,
        contract_address: ContractAddress,
    ) -> StateResult<&ClassHash> {
        if self.cache.get_class_hash_at(contract_address).is_none() {
            let class_hash = self.state_reader.get_class_hash_at(contract_address)?;
            self.cache.set_class_hash_initial_value(contract_address, class_hash);
        }

        let class_hash = self
            .cache
            .get_class_hash_at(contract_address)
            .unwrap_or_else(|| panic!("Cannot retrieve '{contract_address:?}' from the cache."));
        Ok(class_hash)
    }

    pub fn set_contract_hash(
        &mut self,
        contract_address: ContractAddress,
        class_hash: ClassHash,
    ) -> Result<(), StateError> {
        if contract_address == ContractAddress::default() {
            return Err(StateError::OutOfRangeContractAddress);
        }

        let current_class_hash = self.get_class_hash_at(contract_address)?;
        if *current_class_hash != ClassHash::default() {
            return Err(StateError::UnavailableContractAddress(contract_address));
        }

        self.cache.set_class_hash_write(contract_address, class_hash);
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
    fn get_class_hash_at(
        &self,
        _contract_address: ContractAddress,
    ) -> Result<ClassHash, StateReaderError>;
    /// Returns the contract class of the given class hash.
    fn get_contract_class(&self, class_hash: &ClassHash) -> StateReaderResult<Rc<ContractClass>>;
}

type ContractStorageKey = (ContractAddress, StorageKey);

/// A simple implementation of `StateReader` using `HashMap`s for storage.
#[derive(Default)]
pub struct DictStateReader {
    pub storage_view: HashMap<ContractStorageKey, StarkFelt>,
    pub address_to_nonce: HashMap<ContractAddress, Nonce>,
    pub address_to_class_hash: HashMap<ContractAddress, ClassHash>,
    pub class_hash_to_class: ContractClassMapping,
}

impl StateReader for DictStateReader {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> Result<StarkFelt> {
        let contract_storage_key = (contract_address, key);
        let value = self.storage_view.get(&contract_storage_key).copied().unwrap_or_default();
        Ok(value)
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> Result<Nonce> {
        let nonce = self.address_to_nonce.get(&contract_address).copied().unwrap_or_default();
        Ok(nonce)
    }

    fn get_contract_class(&self, class_hash: &ClassHash) -> StateReaderResult<Rc<ContractClass>> {
        let contract_class = self.class_hash_to_class.get(class_hash);
        match contract_class {
            Some(contract_class) => Ok(Rc::clone(contract_class)),
            None => Err(StateReaderError::UndeclaredClassHash(*class_hash)),
        }
    }

    fn get_class_hash_at(
        &self,
        contract_address: ContractAddress,
    ) -> Result<ClassHash, StateReaderError> {
        let class_hash =
            self.address_to_class_hash.get(&contract_address).copied().unwrap_or_default();
        Ok(class_hash)
    }
}

/// Caches read and write requests.
// Invariant: cannot delete keys from fields.
#[derive(Default)]
struct StateCache {
    // Reader's cached information; initial values, read before any write operation (per cell).
    nonce_initial_values: HashMap<ContractAddress, Nonce>,
    class_hash_initial_values: HashMap<ContractAddress, ClassHash>,
    storage_initial_values: HashMap<ContractStorageKey, StarkFelt>,

    // Writer's cached information.
    nonce_writes: HashMap<ContractAddress, Nonce>,
    class_hash_writes: HashMap<ContractAddress, ClassHash>,
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

    fn get_class_hash_at(&self, contract_address: ContractAddress) -> Option<&ClassHash> {
        self.class_hash_writes
            .get(&contract_address)
            .or_else(|| self.class_hash_initial_values.get(&contract_address))
    }

    fn set_class_hash_initial_value(
        &mut self,
        contract_address: ContractAddress,
        class_hash: ClassHash,
    ) {
        self.class_hash_initial_values.insert(contract_address, class_hash);
    }

    fn set_class_hash_write(&mut self, contract_address: ContractAddress, class_hash: ClassHash) {
        self.class_hash_writes.insert(contract_address, class_hash);
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
