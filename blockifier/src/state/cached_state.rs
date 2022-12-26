use std::collections::HashMap;
use std::rc::Rc;

use derive_more::IntoIterator;
use indexmap::IndexMap;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::execution::contract_class::ContractClass;
use crate::state::errors::{StateError, StateReaderError};
use crate::state::state_reader::{StateReader, StateReaderResult};

#[cfg(test)]
#[path = "cached_state_test.rs"]
mod test;

pub type StateResult<T> = Result<T, StateError>;
type ContractClassMapping = HashMap<ClassHash, Rc<ContractClass>>;

/// Caches read and write requests.
///
/// Writer functionality is built-in, whereas Reader functionality is injected through
/// initialization.
#[derive(Clone, Debug, Default)]
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
    ) -> StateResult<&StarkFelt> {
        if self.cache.get_storage_at(contract_address, key).is_none() {
            let storage_value = self.state_reader.get_storage_at(contract_address, key)?;
            self.cache.set_storage_initial_value(contract_address, key, storage_value);
        }

        let value = self.cache.get_storage_at(contract_address, key).unwrap_or_else(|| {
            panic!("Cannot retrieve '{contract_address:?}' and '{key:?}' from the cache.")
        });
        Ok(value)
    }

    pub fn set_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) {
        self.cache.set_storage_value(contract_address, key, value);
    }

    pub fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<&Nonce> {
        if self.cache.get_nonce_at(contract_address).is_none() {
            let nonce = self.state_reader.get_nonce_at(contract_address)?;
            self.cache.set_nonce_initial_value(contract_address, nonce);
        }

        let nonce = self
            .cache
            .get_nonce_at(contract_address)
            .unwrap_or_else(|| panic!("Cannot retrieve '{contract_address:?}' from the cache."));
        Ok(nonce)
    }

    // TODO(Gilad, 1/12/22) consider moving some this logic into starknet-api; Nonce should
    // be able to increment itself.
    pub fn increment_nonce(&mut self, contract_address: ContractAddress) -> StateResult<()> {
        let current_nonce = *self.get_nonce_at(contract_address)?;
        let current_nonce_as_u64 = usize::try_from(current_nonce.0)? as u64;
        let next_nonce_val = 1_u64 + current_nonce_as_u64;
        let next_nonce = Nonce(StarkFelt::from(next_nonce_val));
        self.cache.set_nonce_value(contract_address, next_nonce);

        Ok(())
    }

    pub fn get_contract_class(&mut self, class_hash: &ClassHash) -> StateResult<Rc<ContractClass>> {
        if !self.class_hash_to_class.contains_key(class_hash) {
            let contract_class = self.state_reader.get_contract_class(class_hash)?;
            self.class_hash_to_class.insert(*class_hash, Rc::clone(&contract_class));
        }

        let contract_class = Rc::clone(
            self.class_hash_to_class
                .get(class_hash)
                .expect("The class hash must appear in the cache."),
        );
        Ok(contract_class)
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
    ) -> StateResult<()> {
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

type ContractStorageKey = (ContractAddress, StorageKey);

/// A simple implementation of `StateReader` using `HashMap`s for storage.
#[derive(Clone, Debug, Default)]
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
    ) -> StateReaderResult<StarkFelt> {
        let contract_storage_key = (contract_address, key);
        let value = self.storage_view.get(&contract_storage_key).copied().unwrap_or_default();
        Ok(value)
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateReaderResult<Nonce> {
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

    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateReaderResult<ClassHash> {
        let class_hash =
            self.address_to_class_hash.get(&contract_address).copied().unwrap_or_default();
        Ok(class_hash)
    }
}

#[derive(IntoIterator, Debug, Clone, Default)]
pub struct StorageView(HashMap<ContractStorageKey, StarkFelt>);

/// Converts a `CachedState`'s storage mapping into a `StateDiff`'s storage mapping.
impl From<StorageView> for IndexMap<ContractAddress, IndexMap<StorageKey, StarkFelt>> {
    fn from(storage_view: StorageView) -> Self {
        let mut storage_updates = Self::new();
        for ((address, key), value) in storage_view.into_iter() {
            storage_updates
                .entry(address)
                .and_modify(|map| {
                    map.insert(key, value);
                })
                .or_insert_with(|| IndexMap::from([(key, value)]));
        }

        storage_updates
    }
}

/// Caches read and write requests.
// Invariant: cannot delete keys from fields.
#[derive(Clone, Debug, Default)]
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

    fn get_nonce_at(&self, contract_address: ContractAddress) -> Option<&Nonce> {
        self.nonce_writes
            .get(&contract_address)
            .or_else(|| self.nonce_initial_values.get(&contract_address))
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
