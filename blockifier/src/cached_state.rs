use std::collections::HashMap;

use anyhow::Result;
use starknet_api::{ClassHash, ContractAddress, Nonce, StarkFelt, StorageKey};

/// Caches read and write requests.
///
/// Writer functionality is built-in, whereas Reader functionality is injected through
/// initialization.
pub struct CachedState<SR: StateReader> {
    pub state_reader: SR,
    // Invariant: the cache should remain private.
    _cache: StateCache,
}

impl<SR: StateReader> CachedState<SR> {
    pub fn new(state_reader: SR) -> Self {
        Self { state_reader, _cache: StateCache::default() }
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
