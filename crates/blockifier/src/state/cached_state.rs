use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use cached::{Cached, SizedCache};
use derive_more::IntoIterator;
use indexmap::IndexMap;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::abi::abi_utils::get_fee_token_var_address;
use crate::execution::contract_class::ContractClass;
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader, StateResult};
use crate::utils::subtract_mappings;

#[cfg(test)]
#[path = "cached_state_test.rs"]
mod test;

/// Caches read and write requests.
///
/// Writer functionality is builtin, whereas Reader functionality is injected through
/// initialization.
pub struct CachedState<S: StateReader> {
    pub state: S,
    // StateChache internaly manages multiple source of data
    // and copy from one to the other as it is read from.
    // It therefore needs interior mutability in order keep doing that while
    // implementing the `StateReader` trait.
    // Whenever you own a mutable reference to self, there is no trouble:
    // `let cache = self.cache.get_mut();`
    // But then you don't, do the following :
    // ```
    // let mut cache = self.cache.take();
    // // Execute your logic here. You fully own cache.
    // // Before returning, don't forget to store the cache back into `self`.
    // self.cache.set(cache);
    // ```
    cache: Cell<StateCache>,
}

impl<S: StateReader> CachedState<S> {
    pub fn new(state: S, global_class_hash_to_class: GlobalContractCache) -> Self {
        Self { state, cache: Cell::new(StateCache::new(global_class_hash_to_class)) }
    }

    /// Creates a transactional instance from the given cached state.
    /// It allows performing buffered modifying actions on the given state, which
    /// will either all happen (will be committed) or none of them (will be discarded).
    pub fn create_transactional(state: &mut CachedState<S>) -> TransactionalState<'_, S> {
        let global_class_hash_to_class = state.cache.get_mut().global_class_hash_to_class.clone();
        CachedState::new(MutRefState::new(state), global_class_hash_to_class)
    }

    /// Returns the storage changes done through this state.
    /// For each contract instance (address) we have three attributes: (class hash, nonce, storage
    /// root); the state updates correspond to them.
    pub fn get_actual_state_changes_for_fee_charge(
        &mut self,
        fee_token_address: ContractAddress,
        sender_address: Option<ContractAddress>,
    ) -> StateResult<StateChanges> {
        self.update_initial_values_of_write_only_access()?;
        let cache = self.cache.get_mut();

        // Storage Update.
        let mut storage_updates = cache.get_storage_updates();
        let mut modified_contracts: HashSet<ContractAddress> =
            storage_updates.keys().map(|address_key_pair| address_key_pair.0).collect();

        // Class hash Update (deployed contracts + replace_class syscall).
        let class_hash_updates = cache.get_class_hash_updates();
        modified_contracts.extend(class_hash_updates.keys());

        // Nonce updates.
        let nonce_updates = cache.get_nonce_updates();
        modified_contracts.extend(nonce_updates.keys());

        // Compiled class hash updates (declare Cairo 1 contract).
        let compiled_class_hash_updates = cache.get_compiled_class_hash_updates();

        // For account transactions, we need to compute the transaction fee before we can execute
        // the fee transfer, and the fee should cover the state changes that happen in the
        // fee transfer. The fee transfer is going to update the balance of the sequencer
        // and the balance of the sender contract, but we don't charge the sender for the
        // sequencer balance change as it is amortized across the block.
        if let Some(sender_address) = sender_address {
            let sender_balance_key = get_fee_token_var_address(sender_address);
            // StarkFelt::default() value is zero, which must be different from the initial balance,
            // otherwise the transaction would have failed the "max fee lower than
            // balance" validation.
            storage_updates.insert((fee_token_address, sender_balance_key), StarkFelt::default());
        }

        // Exclude the fee token contract modification, since it’s charged once throughout the
        // block.
        modified_contracts.remove(&fee_token_address);

        Ok(StateChanges {
            storage_updates: storage_updates.clone(),
            modified_contracts,
            class_hash_updates: class_hash_updates.clone(),
            compiled_class_hash_updates,
        })
    }

    pub fn move_classes_to_global_cache(&mut self) {
        self.cache.get_mut().move_classes_to_global_cache();
    }

    pub fn update_contract_class_caches(
        &mut self,
        local_contract_cache_updates: ContractClassMapping,
        global_contract_cache: GlobalContractCache,
    ) {
        self.cache
            .get_mut()
            .update_contract_class_caches(local_contract_cache_updates, global_contract_cache);
    }

    pub fn update_cache(&mut self, cache_updates: StateCache) {
        let cache = self.cache.get_mut();
        cache.nonce_writes.extend(cache_updates.nonce_writes);
        cache.class_hash_writes.extend(cache_updates.class_hash_writes);
        cache.storage_writes.extend(cache_updates.storage_writes);
        cache.compiled_class_hash_writes.extend(cache_updates.compiled_class_hash_writes);
    }

    /// Updates cache with initial cell values for write-only access.
    /// If written values match the original, the cell is unchanged and not counted as a
    /// storage-change for fee calculation.
    /// Same for class hash and nonce writes.
    // TODO(Noa, 30/07/23): Consider adding DB getters in bulk (via a DB read transaction).
    fn update_initial_values_of_write_only_access(&mut self) -> StateResult<()> {
        // Eliminate storage writes that are identical to the initial value (no change). Assumes
        // that `set_storage_at` does not affect the state field.
        let cache = self.cache.get_mut();

        for contract_storage_key in cache.storage_writes.keys() {
            if !cache.storage_initial_values.contains_key(contract_storage_key) {
                // First access to this cell was write; cache initial value.
                cache.storage_initial_values.insert(
                    *contract_storage_key,
                    self.state.get_storage_at(contract_storage_key.0, contract_storage_key.1)?,
                );
            }
        }

        for contract_address in cache.class_hash_writes.keys() {
            if !cache.class_hash_initial_values.contains_key(contract_address) {
                // First access to this cell was write; cache initial value.
                cache
                    .class_hash_initial_values
                    .insert(*contract_address, self.state.get_class_hash_at(*contract_address)?);
            }
        }

        for contract_address in cache.nonce_writes.keys() {
            if !cache.nonce_initial_values.contains_key(contract_address) {
                // First access to this cell was write; cache initial value.
                cache
                    .nonce_initial_values
                    .insert(*contract_address, self.state.get_nonce_at(*contract_address)?);
            }
        }

        Ok(())
    }
}

impl<S: StateReader> From<S> for CachedState<S> {
    fn from(state_reader: S) -> Self {
        CachedState::new(state_reader, Default::default())
    }
}

impl<S: StateReader> StateReader for CachedState<S> {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        let mut cache = self.cache.take();

        let mut closure_get_storage = || {
            let storage_value =
                if let Some(storage_value) = cache.get_opt_storage_at(contract_address, key) {
                    *storage_value
                } else {
                    let storage_value = self.state.get_storage_at(contract_address, key)?;
                    cache.set_storage_initial_value(contract_address, key, storage_value);
                    storage_value
                };

            Ok(storage_value)
        };
        let res_storage_value = closure_get_storage();

        self.cache.set(cache);
        res_storage_value
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        let mut cache = self.cache.take();

        let mut closure_get_nonce = || {
            let nonce = if let Some(nonce) = cache.get_opt_nonce_at(contract_address) {
                *nonce
            } else {
                let nonce = self.state.get_nonce_at(contract_address)?;
                cache.set_nonce_initial_value(contract_address, nonce);
                nonce
            };

            Ok(nonce)
        };

        let res_nonce = closure_get_nonce();
        self.cache.set(cache);
        res_nonce
    }

    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        let mut cache = self.cache.take();

        let mut closure_get_class_at = || {
            let class_hash =
                if let Some(class_hash) = cache.get_opt_class_hash_at(contract_address).cloned() {
                    class_hash
                } else {
                    let class_hash = self.state.get_class_hash_at(contract_address)?;
                    cache.set_class_hash_initial_value(contract_address, class_hash);
                    class_hash
                };

            Ok(class_hash)
        };
        let res_class_hash = closure_get_class_at();

        self.cache.set(cache);
        res_class_hash
    }

    fn get_compiled_contract_class(&self, class_hash: ClassHash) -> StateResult<ContractClass> {
        let mut cache = self.cache.take();

        let mut closure_get_contract_class = || {
            if let Some(contract_class) = cache.class_hash_to_class.get(&class_hash) {
                return Ok(contract_class.clone());
            }

            let contract_class = {
                let mut global_class_hash_to_class = cache.global_class_hash_to_class();
                global_class_hash_to_class.cache_get(&class_hash).cloned()
            };

            let contract_class = match contract_class {
                Some(contract_class_from_global_cache) => {
                    cache
                        .class_hash_to_class
                        .insert(class_hash, contract_class_from_global_cache.clone());
                    contract_class_from_global_cache
                }
                None => {
                    let contract_class_from_db =
                        self.state.get_compiled_contract_class(class_hash)?;
                    cache.class_hash_to_class.insert(class_hash, contract_class_from_db.clone());
                    contract_class_from_db
                }
            };
            Ok(contract_class)
        };
        let res_contract_class = closure_get_contract_class();

        self.cache.set(cache);
        res_contract_class
    }

    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        let mut cache = self.cache.take();

        let mut closure_get_class_hash = || {
            let compiled_class_hash =
                if let Some(compiled_class_hash) = cache.get_opt_compiled_class_hash(class_hash) {
                    *compiled_class_hash
                } else {
                    let compiled_class_hash = self.state.get_compiled_class_hash(class_hash)?;
                    cache.set_compiled_class_hash_initial_value(class_hash, compiled_class_hash);
                    compiled_class_hash
                };
            Ok(compiled_class_hash)
        };
        let res_class_hash = closure_get_class_hash();

        self.cache.set(cache);
        res_class_hash
    }
}

impl<S: StateReader> State for CachedState<S> {
    fn set_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) -> StateResult<()> {
        self.cache.get_mut().set_storage_at(contract_address, key, value)
    }

    fn increment_nonce(&mut self, contract_address: ContractAddress) -> StateResult<()> {
        let current_nonce = self.get_nonce_at(contract_address)?;
        let current_nonce_as_u64 = usize::try_from(current_nonce.0)? as u64;
        let next_nonce_val = 1_u64 + current_nonce_as_u64;
        let next_nonce = Nonce(StarkFelt::from(next_nonce_val));
        self.cache.get_mut().set_nonce_value(contract_address, next_nonce);

        Ok(())
    }

    fn set_class_hash_at(
        &mut self,
        contract_address: ContractAddress,
        class_hash: ClassHash,
    ) -> StateResult<()> {
        if contract_address == ContractAddress::default() {
            return Err(StateError::OutOfRangeContractAddress);
        }

        self.cache.get_mut().set_class_hash_write(contract_address, class_hash);

        Ok(())
    }

    fn set_contract_class(
        &mut self,
        class_hash: ClassHash,
        contract_class: ContractClass,
    ) -> StateResult<()> {
        self.cache.get_mut().set_contract_class(class_hash, contract_class)
    }

    fn set_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
    ) -> StateResult<()> {
        self.cache.get_mut().set_compiled_class_hash(class_hash, compiled_class_hash)
    }
}

impl<S: StateReader> CachedState<S> {
    pub fn cached_state_diff(&mut self) -> CommitmentStateDiff {
        type StorageDiff = IndexMap<ContractAddress, IndexMap<StorageKey, StarkFelt>>;

        // TODO(Gilad): Consider returning an error here, would require changing the API though.
        self.update_initial_values_of_write_only_access()
            .unwrap_or_else(|_| panic!("Cannot convert stateDiff to CommitmentStateDiff."));

        let state_cache = self.cache.get_mut();
        let class_hash_updates = state_cache.get_class_hash_updates();
        let storage_diffs = state_cache.get_storage_updates();
        let nonces =
            subtract_mappings(&state_cache.nonce_writes, &state_cache.nonce_initial_values);
        let declared_classes = state_cache.compiled_class_hash_writes.clone();

        CommitmentStateDiff {
            address_to_class_hash: IndexMap::from_iter(class_hash_updates),
            storage_updates: StorageDiff::from(StorageView(storage_diffs)),
            class_hash_to_compiled_class_hash: IndexMap::from_iter(declared_classes),
            address_to_nonce: IndexMap::from_iter(nonces),
        }
    }
}

#[cfg(any(feature = "testing", test))]
impl Default for CachedState<crate::test_utils::dict_state_reader::DictStateReader> {
    fn default() -> Self {
        Self { state: Default::default(), cache: Default::default() }
    }
}

pub type StorageEntry = (ContractAddress, StorageKey);

#[derive(Debug, Default, IntoIterator)]
pub struct StorageView(pub HashMap<StorageEntry, StarkFelt>);

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

pub type ContractClassMapping = HashMap<ClassHash, ContractClass>;

/// Caches read and write requests.
/// The tracked changes are needed for block state commitment.

// Invariant: keys cannot be deleted from fields (only used internally by the cached state).
#[derive(Debug, Default)]
pub struct StateCache {
    class_hash_to_class: ContractClassMapping,
    // Invariant: managed by CachedState.
    global_class_hash_to_class: GlobalContractCache,

    // Reader's cached information; initial values, read before any write operation (per cell).
    nonce_initial_values: HashMap<ContractAddress, Nonce>,
    class_hash_initial_values: HashMap<ContractAddress, ClassHash>,
    storage_initial_values: HashMap<StorageEntry, StarkFelt>,
    compiled_class_hash_initial_values: HashMap<ClassHash, CompiledClassHash>,

    // Writer's cached information.
    nonce_writes: HashMap<ContractAddress, Nonce>,
    class_hash_writes: HashMap<ContractAddress, ClassHash>,
    storage_writes: HashMap<StorageEntry, StarkFelt>,
    compiled_class_hash_writes: HashMap<ClassHash, CompiledClassHash>,
}

impl StateReader for StateCache {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        let storage_value =
            self.get_opt_storage_at(contract_address, key).cloned().unwrap_or(StarkFelt::ZERO);

        Ok(storage_value)
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        let nonce =
            self.get_opt_nonce_at(contract_address).cloned().unwrap_or(Nonce(StarkFelt::ZERO));

        Ok(nonce)
    }

    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        let class_hash = self
            .get_opt_class_hash_at(contract_address)
            .cloned()
            .unwrap_or(ClassHash(StarkFelt::ZERO));

        Ok(class_hash)
    }

    fn get_compiled_contract_class(&self, class_hash: ClassHash) -> StateResult<ContractClass> {
        self.get_opt_compiled_contract_class(class_hash)
            .ok_or(StateError::UndeclaredClassHash(class_hash))
    }

    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        self.get_opt_compiled_class_hash(class_hash)
            .cloned()
            .ok_or(StateError::UndeclaredClassHash(class_hash))
    }
}

impl State for StateCache {
    fn set_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) -> StateResult<()> {
        let contract_storage_key = (contract_address, key);
        self.storage_writes.insert(contract_storage_key, value);
        Ok(())
    }

    fn increment_nonce(&mut self, contract_address: ContractAddress) -> StateResult<()> {
        let current_nonce = self.get_nonce_at(contract_address)?;
        let new_nonce = u64::try_from(current_nonce.0)? + 1;
        self.set_nonce_value(contract_address, Nonce(new_nonce.into()));

        Ok(())
    }

    fn set_class_hash_at(
        &mut self,
        contract_address: ContractAddress,
        class_hash: ClassHash,
    ) -> StateResult<()> {
        self.set_class_hash_write(contract_address, class_hash);
        Ok(())
    }

    fn set_contract_class(
        &mut self,
        class_hash: ClassHash,
        contract_class: ContractClass,
    ) -> StateResult<()> {
        self.set_contract_class_write(class_hash, contract_class);
        Ok(())
    }

    fn set_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
    ) -> StateResult<()> {
        self.set_compiled_class_hash_write(class_hash, compiled_class_hash);
        Ok(())
    }
}

impl StateCache {
    pub fn new(global_class_hash_to_class: GlobalContractCache) -> Self {
        Self {
            class_hash_to_class: Default::default(),
            global_class_hash_to_class,
            nonce_initial_values: Default::default(),
            class_hash_initial_values: Default::default(),
            storage_initial_values: Default::default(),
            compiled_class_hash_initial_values: Default::default(),
            nonce_writes: Default::default(),
            class_hash_writes: Default::default(),
            storage_writes: Default::default(),
            compiled_class_hash_writes: Default::default(),
        }
    }

    /// Drains contract-class cache collected during execution and updates the global cache.
    fn move_classes_to_global_cache(&mut self) {
        let contract_class_updates: Vec<_> = self.class_hash_to_class.drain().collect();
        for (key, value) in contract_class_updates {
            self.global_class_hash_to_class().cache_set(key, value);
        }
    }

    // Locks the Mutex and unwraps the MutexGuard, thus exposing the internal cache
    // store. The Guard will panic only if the Mutex panics during the lock operation, but
    // this shouldn't happen in our flow.
    // Note: `&mut` is used since the LRU cache updates internal counters on reads.
    pub fn global_class_hash_to_class(
        &self,
    ) -> MutexGuard<'_, SizedCache<ClassHash, ContractClass>> {
        self.global_class_hash_to_class.lock().expect("Global contract cache is poisoned.")
    }

    fn update_contract_class_caches(
        &mut self,
        local_contract_cache_updates: ContractClassMapping,
        global_contract_cache: GlobalContractCache,
    ) {
        self.class_hash_to_class.extend(local_contract_cache_updates);
        self.global_class_hash_to_class = global_contract_cache;
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

    fn get_opt_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> Option<&StarkFelt> {
        let contract_storage_key = (contract_address, key);
        self.storage_writes
            .get(&contract_storage_key)
            .or_else(|| self.storage_initial_values.get(&contract_storage_key))
    }

    fn get_opt_nonce_at(&self, contract_address: ContractAddress) -> Option<&Nonce> {
        self.nonce_writes
            .get(&contract_address)
            .or_else(|| self.nonce_initial_values.get(&contract_address))
    }

    fn get_opt_class_hash_at(&self, contract_address: ContractAddress) -> Option<&ClassHash> {
        self.class_hash_writes
            .get(&contract_address)
            .or_else(|| self.class_hash_initial_values.get(&contract_address))
    }

    fn get_opt_compiled_class_hash(&self, class_hash: ClassHash) -> Option<&CompiledClassHash> {
        self.compiled_class_hash_writes
            .get(&class_hash)
            .or_else(|| self.compiled_class_hash_initial_values.get(&class_hash))
    }

    fn get_opt_compiled_contract_class(&self, class_hash: ClassHash) -> Option<ContractClass> {
        self.class_hash_to_class
            .get(&class_hash)
            .cloned()
            .or_else(|| self.global_class_hash_to_class().cache_get(&class_hash).cloned())
    }

    fn set_nonce_initial_value(&mut self, contract_address: ContractAddress, nonce: Nonce) {
        self.nonce_initial_values.insert(contract_address, nonce);
    }

    fn set_nonce_value(&mut self, contract_address: ContractAddress, nonce: Nonce) {
        self.nonce_writes.insert(contract_address, nonce);
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

    fn set_compiled_class_hash_initial_value(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
    ) {
        self.compiled_class_hash_initial_values.insert(class_hash, compiled_class_hash);
    }

    fn set_compiled_class_hash_write(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
    ) {
        self.compiled_class_hash_writes.insert(class_hash, compiled_class_hash);
    }

    fn set_contract_class_write(&mut self, class_hash: ClassHash, contract_class: ContractClass) {
        self.class_hash_to_class.insert(class_hash, contract_class);
    }

    fn get_storage_updates(&self) -> HashMap<StorageEntry, StarkFelt> {
        subtract_mappings(&self.storage_writes, &self.storage_initial_values)
    }

    fn get_class_hash_updates(&self) -> HashMap<ContractAddress, ClassHash> {
        subtract_mappings(&self.class_hash_writes, &self.class_hash_initial_values)
    }

    fn get_nonce_updates(&self) -> HashMap<ContractAddress, Nonce> {
        subtract_mappings(&self.nonce_writes, &self.nonce_initial_values)
    }

    fn get_compiled_class_hash_updates(&self) -> HashMap<ClassHash, CompiledClassHash> {
        subtract_mappings(
            &self.compiled_class_hash_writes,
            &self.compiled_class_hash_initial_values,
        )
    }
}

/// Wraps a mutable reference to a `State` object, exposing its API.
/// Used to pass ownership to a `CachedState`.
pub struct MutRefState<'a, S: State + ?Sized>(&'a mut S);

impl<'a, S: State + ?Sized> MutRefState<'a, S> {
    pub fn new(state: &'a mut S) -> Self {
        Self(state)
    }
}

/// Proxies inner object to expose `State` functionality.
impl<'a, S: State + ?Sized> StateReader for MutRefState<'a, S> {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        self.0.get_storage_at(contract_address, key)
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        self.0.get_nonce_at(contract_address)
    }

    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        self.0.get_class_hash_at(contract_address)
    }

    fn get_compiled_contract_class(&self, class_hash: ClassHash) -> StateResult<ContractClass> {
        self.0.get_compiled_contract_class(class_hash)
    }

    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        self.0.get_compiled_class_hash(class_hash)
    }
}

impl<'a, S: State + ?Sized> State for MutRefState<'a, S> {
    fn set_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) -> StateResult<()> {
        self.0.set_storage_at(contract_address, key, value)
    }

    fn increment_nonce(&mut self, contract_address: ContractAddress) -> StateResult<()> {
        self.0.increment_nonce(contract_address)
    }

    fn set_class_hash_at(
        &mut self,
        contract_address: ContractAddress,
        class_hash: ClassHash,
    ) -> StateResult<()> {
        self.0.set_class_hash_at(contract_address, class_hash)
    }

    fn set_contract_class(
        &mut self,
        class_hash: ClassHash,
        contract_class: ContractClass,
    ) -> StateResult<()> {
        self.0.set_contract_class(class_hash, contract_class)
    }

    fn set_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
    ) -> StateResult<()> {
        self.0.set_compiled_class_hash(class_hash, compiled_class_hash)
    }
}

pub type TransactionalState<'a, S> = CachedState<MutRefState<'a, CachedState<S>>>;

impl<'a, S: StateReader> TransactionalState<'a, S> {
    // Detach `state`, moving the instance to a pending state, which can be committed or aborted.
    pub fn stage(
        self,
        tx_executed_class_hashes: HashSet<ClassHash>,
        tx_visited_storage_entries: HashSet<StorageEntry>,
    ) -> StagedTransactionalState {
        let TransactionalState { cache, .. } = self;
        let cache = cache.into_inner();

        let class_hash_to_class = cache.class_hash_to_class.clone();
        let global_class_hash_to_class = cache.global_class_hash_to_class.clone();

        StagedTransactionalState {
            cache,
            class_hash_to_class,
            global_class_hash_to_class,
            tx_executed_class_hashes,
            tx_visited_storage_entries,
        }
    }

    /// Commits changes in the child (wrapping) state to its parent.
    pub fn commit(self) {
        let state = self.state.0;
        let cache = self.cache.into_inner();

        let class_hash_to_class = cache.class_hash_to_class.clone();
        let global_class_hash_to_class = cache.global_class_hash_to_class.clone();

        // Write wrapper cache to state
        state.update_cache(cache);

        // Write wrapper contract class to state
        state
            .cache
            .get_mut()
            .update_contract_class_caches(class_hash_to_class, global_class_hash_to_class)
    }

    /// Drops `self`.
    pub fn abort(self) {}
}

/// Represents the interim state, containing the changes made by a transaction after execution but
/// before commitment to the state. Can be passed to external services that validate and count
/// resources to decide whether the transaction should be committed or aborted.
pub struct StagedTransactionalState {
    pub cache: StateCache,
    pub class_hash_to_class: ContractClassMapping,
    pub global_class_hash_to_class: GlobalContractCache,

    // Maintained for counting purposes.
    pub tx_executed_class_hashes: HashSet<ClassHash>,
    pub tx_visited_storage_entries: HashSet<StorageEntry>,
}

/// Holds uncommitted changes induced on Starknet contracts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentStateDiff {
    // Contract instance attributes (per address).
    pub address_to_class_hash: IndexMap<ContractAddress, ClassHash>,
    pub address_to_nonce: IndexMap<ContractAddress, Nonce>,
    pub storage_updates: IndexMap<ContractAddress, IndexMap<StorageKey, StarkFelt>>,

    // Global attributes.
    pub class_hash_to_compiled_class_hash: IndexMap<ClassHash, CompiledClassHash>,
}

/// Holds the state changes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StateChanges {
    pub storage_updates: HashMap<StorageEntry, StarkFelt>,
    pub class_hash_updates: HashMap<ContractAddress, ClassHash>,
    pub compiled_class_hash_updates: HashMap<ClassHash, CompiledClassHash>,
    pub modified_contracts: HashSet<ContractAddress>,
}

impl StateChanges {
    /// Merges the given state changes into a single one. Note that the order of the state changes
    /// is important. The state changes are merged in the order they appear in the given vector.
    pub fn merge(state_changes: Vec<Self>) -> Self {
        let mut merged_state_changes = Self::default();
        for state_change in state_changes {
            merged_state_changes.storage_updates.extend(state_change.storage_updates);
            merged_state_changes.class_hash_updates.extend(state_change.class_hash_updates);
            merged_state_changes
                .compiled_class_hash_updates
                .extend(state_change.compiled_class_hash_updates);
            merged_state_changes.modified_contracts.extend(state_change.modified_contracts);
        }

        merged_state_changes
    }
}

/// Holds the number of state changes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StateChangesCount {
    pub n_storage_updates: usize,
    pub n_class_hash_updates: usize,
    pub n_compiled_class_hash_updates: usize,
    pub n_modified_contracts: usize,
}

impl From<&StateChanges> for StateChangesCount {
    fn from(state_changes: &StateChanges) -> Self {
        Self {
            n_storage_updates: state_changes.storage_updates.len(),
            n_class_hash_updates: state_changes.class_hash_updates.len(),
            n_compiled_class_hash_updates: state_changes.compiled_class_hash_updates.len(),
            n_modified_contracts: state_changes.modified_contracts.len(),
        }
    }
}

// Note: `ContractClassLRUCache` key-value types must align with `ContractClassMapping`.
type ContractClassLRUCache = SizedCache<ClassHash, ContractClass>;
#[derive(Debug, Clone, derive_more::Deref, derive_more::DerefMut)]
// Thread-safe LRU cache for contract classes, optimized for inter-language sharing when
// `blockifier` compiles as a shared library.
pub struct GlobalContractCache(pub Arc<Mutex<ContractClassLRUCache>>);

impl GlobalContractCache {
    // TODO: make this configurable via a CachedState constructor argument.
    const CACHE_SIZE: usize = 100;
}

impl Default for GlobalContractCache {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(ContractClassLRUCache::with_size(Self::CACHE_SIZE))))
    }
}
