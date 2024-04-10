use std::sync::{Arc, Mutex, MutexGuard};

use cached::{Cached, SizedCache};
use starknet_api::core::ClassHash;

use crate::execution::contract_class::ContractClass;

// Note: `ContractClassLRUCache` key-value types must align with `ContractClassMapping`.
type ContractClassLRUCache = SizedCache<ClassHash, ContractClass>;
pub type LockedContractClassCache<'a> = MutexGuard<'a, ContractClassLRUCache>;
#[derive(Debug, Clone)]
// Thread-safe LRU cache for contract classes, optimized for inter-language sharing when
// `blockifier` compiles as a shared library.
// TODO(Yoni, 1/1/2025): consider defining CachedStateReader.
pub struct GlobalContractCache(pub Arc<Mutex<ContractClassLRUCache>>);

pub const GLOBAL_CONTRACT_CACHE_SIZE_FOR_TEST: usize = 100;

impl GlobalContractCache {
    /// Locks the cache for atomic access. Although conceptually shared, writing to this cache is
    /// only possible for one writer at a time.
    pub fn lock(&self) -> LockedContractClassCache<'_> {
        self.0.lock().expect("Global contract cache is poisoned.")
    }

    pub fn get(&self, class_hash: &ClassHash) -> Option<ContractClass> {
        self.lock().cache_get(class_hash).cloned()
    }

    pub fn set(&self, class_hash: ClassHash, contract_class: ContractClass) {
        self.lock().cache_set(class_hash, contract_class);
    }

    pub fn clear(&mut self) {
        self.lock().cache_clear();
    }

    pub fn new(cache_size: usize) -> Self {
        Self(Arc::new(Mutex::new(ContractClassLRUCache::with_size(cache_size))))
    }
}
