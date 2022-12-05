use std::collections::HashMap;
use std::rc::Rc;

use anyhow::Result;
use starknet_api::{ClassHash, ContractAddress, ContractClass, Nonce, StarkFelt, StorageKey};

/// Caches read and write requests.
///
/// Writer functionality is built-in, whereas Reader functionality is injected through
/// initialization.
pub struct CachedState<SR: StateReader> {
    pub state_reader: SR,
    // Invariant: the cache should remain private.
    _cache: StateCache,
    contract_classes: HashMap<ClassHash, Rc<ContractClass>>,
}

impl<SR: StateReader> CachedState<SR> {
    pub fn new(state_reader: SR) -> Self {
        Self { state_reader, _cache: StateCache::default(), contract_classes: HashMap::default() }
    }

    pub fn get_contract_class(
        &mut self,
        contract_hash: &ClassHash,
    ) -> Result<Option<Rc<ContractClass>>> {
        if !self.contract_classes.contains_key(contract_hash) {
            let contract_class = self.state_reader.get_contract_class(contract_hash)?;
            match contract_class {
                None => return Ok(None),
                Some(contract_class) => {
                    self.contract_classes.insert(*contract_hash, Rc::clone(&contract_class));
                }
            }
        }
        Ok(Some(Rc::clone(self.contract_classes.get(contract_hash).unwrap())))
    }
}

/// A read-only API for accessing StarkNet global state.
pub trait StateReader {
    /// Returns the storage value under the given key in the given contract instance (represented by
    /// its address).
    fn get_storage_at(
        &self,
        _contract_address: ContractAddress,
        _key: StorageKey,
    ) -> Result<StarkFelt> {
        unimplemented!();
    }

    /// Returns the nonce of the given contract instance.
    fn get_nonce_at(&self, _contract_address: ContractAddress) -> Result<Nonce> {
        unimplemented!();
    }

    /// Returns the class hash of the contract class at the given contract instance;
    /// uninitialized class hash, if the address is unassigned.
    fn get_class_hash_at(&self, _contract_address: ContractAddress) -> Result<ClassHash> {
        unimplemented!();
    }

    /// Returns the contract class of the given class hash; None if the class hash is uninitialized.
    fn get_contract_class(&self, _contract_hash: &ClassHash) -> Result<Option<Rc<ContractClass>>> {
        unimplemented!()
    }
}

// Used internally by `StateCache`.
type ContractStorageKey = (ContractAddress, StorageKey);

/// Caches read and write requests.
// Invariant: cannot delete keys from fields.
#[derive(Default)]
struct StateCache {
    // Reader's cached information; initial values, read before any write operation (per cell).
    _nonce_initial_values: HashMap<ContractAddress, Nonce>,
    _class_hash_initial_values: HashMap<ContractAddress, ClassHash>,
    _storage_initial_values: HashMap<ContractStorageKey, StarkFelt>,

    // Writer's cached information.
    _nonce_writes: HashMap<ContractAddress, Nonce>,
    _class_hash_writes: HashMap<ContractAddress, ClassHash>,
    _storage_writes: HashMap<ContractStorageKey, StarkFelt>,
}
