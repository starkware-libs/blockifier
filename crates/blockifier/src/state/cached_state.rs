use std::collections::{HashMap, HashSet};

use derive_more::IntoIterator;
use indexmap::IndexMap;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::abi::abi_utils::get_erc20_balance_var_addresses;
use crate::execution::contract_class::ContractClass;
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader, StateResult};
use crate::utils::subtract_mappings;

#[cfg(test)]
#[path = "cached_state_test.rs"]
mod test;

pub type ContractClassMapping = HashMap<ClassHash, ContractClass>;

/// Caches read and write requests.
///
/// Writer functionality is builtin, whereas Reader functionality is injected through
/// initialization.
#[derive(Debug)]
pub struct CachedState<S: StateReader> {
    pub state: S,
    // Invariant: read/write access is managed by CachedState.
    cache: StateCache,
    class_hash_to_class: ContractClassMapping,
}

impl<S: StateReader> CachedState<S> {
    pub fn new(state: S) -> Self {
        Self { state, cache: StateCache::default(), class_hash_to_class: HashMap::default() }
    }

    /// Creates a transactional instance from the given cached state.
    /// It allows performing buffered modifying actions on the given state, which
    /// will either all happen (will be committed) or none of them (will be discarded).
    pub fn create_transactional(state: &mut CachedState<S>) -> TransactionalState<'_, S> {
        CachedState::new(MutRefState::new(state))
    }

    /// Returns the number of storage changes done through this state.
    /// For each contract instance (address) we have three attributes: (class hash, nonce, storage
    /// root); the state updates correspond to them.
    pub fn count_actual_state_changes(
        &mut self,
        fee_token_address: ContractAddress,
        sender_address: Option<ContractAddress>,
    ) -> StateResult<StateChanges> {
        self.update_initial_values_of_write_only_access()?;

        // Storage Update.
        let storage_updates = &mut self.cache.get_storage_updates();
        if let Some(sender_address) = sender_address {
            // Remove sender's balance update from storage updates since we consider it when
            // calculating the storage updates done in the fee transfer.
            let (low_key, _high_key) = get_erc20_balance_var_addresses(&sender_address)?;
            storage_updates.remove(&(fee_token_address, low_key));
        }
        let mut modified_contracts: HashSet<ContractAddress> =
            storage_updates.keys().map(|address_key_pair| address_key_pair.0).collect();

        // Class hash Update (deployed contracts + replace_class syscall).
        let class_hash_updates = &self.cache.get_class_hash_updates();
        modified_contracts.extend(class_hash_updates.keys());

        // Nonce updates.
        let nonce_updates = &self.cache.get_nonce_updates();
        modified_contracts.extend(nonce_updates.keys());

        // Exclude the fee token contract modification since it’s charged once throughout the block.
        modified_contracts.remove(&fee_token_address);

        Ok(StateChanges {
            n_storage_updates: storage_updates.len(),
            n_modified_contracts: modified_contracts.len(),
            n_class_hash_updates: class_hash_updates.len(),
            n_nonce_updates: nonce_updates.len(),
        })
    }

    /// Updates cache with initial cell values for write-only access.
    /// If written values match the original, the cell is unchanged and not counted as a
    /// storage-change for fee calculation.
    /// Same for class hash and nonce writes.
    // TODO(Noa, 30/07/23): Consider adding DB getters in bulk (via a DB read transaction).
    fn update_initial_values_of_write_only_access(&mut self) -> StateResult<()> {
        // Eliminate storage writes that are identical to the initial value (no change). Assumes
        // that `set_storage_at` does not affect the state field.
        for contract_storage_key in self.cache.storage_writes.keys() {
            if !self.cache.storage_initial_values.contains_key(contract_storage_key) {
                // First access to this cell was write; cache initial value.
                self.cache.storage_initial_values.insert(
                    *contract_storage_key,
                    self.state.get_storage_at(contract_storage_key.0, contract_storage_key.1)?,
                );
            }
        }

        for contract_address in self.cache.class_hash_writes.keys() {
            if !self.cache.class_hash_initial_values.contains_key(contract_address) {
                // First access to this cell was write; cache initial value.
                self.cache
                    .class_hash_initial_values
                    .insert(*contract_address, self.state.get_class_hash_at(*contract_address)?);
            }
        }

        for contract_address in self.cache.nonce_writes.keys() {
            if !self.cache.nonce_initial_values.contains_key(contract_address) {
                // First access to this cell was write; cache initial value.
                self.cache
                    .nonce_initial_values
                    .insert(*contract_address, self.state.get_nonce_at(*contract_address)?);
            }
        }

        Ok(())
    }
}

impl<S: StateReader> StateReader for CachedState<S> {
    fn get_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        if self.cache.get_storage_at(contract_address, key).is_none() {
            let storage_value = self.state.get_storage_at(contract_address, key)?;
            self.cache.set_storage_initial_value(contract_address, key, storage_value);
        }

        let value = self.cache.get_storage_at(contract_address, key).unwrap_or_else(|| {
            panic!("Cannot retrieve '{contract_address:?}' and '{key:?}' from the cache.")
        });
        Ok(*value)
    }

    fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce> {
        if self.cache.get_nonce_at(contract_address).is_none() {
            let nonce = self.state.get_nonce_at(contract_address)?;
            self.cache.set_nonce_initial_value(contract_address, nonce);
        }

        let nonce = self
            .cache
            .get_nonce_at(contract_address)
            .unwrap_or_else(|| panic!("Cannot retrieve '{contract_address:?}' from the cache."));
        Ok(*nonce)
    }

    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        if self.cache.get_class_hash_at(contract_address).is_none() {
            let class_hash = self.state.get_class_hash_at(contract_address)?;
            self.cache.set_class_hash_initial_value(contract_address, class_hash);
        }

        let class_hash = self
            .cache
            .get_class_hash_at(contract_address)
            .unwrap_or_else(|| panic!("Cannot retrieve '{contract_address:?}' from the cache."));
        Ok(*class_hash)
    }

    fn get_compiled_contract_class(
        &mut self,
        class_hash: &ClassHash,
    ) -> StateResult<ContractClass> {
        if !self.class_hash_to_class.contains_key(class_hash) {
            let contract_class = self.state.get_compiled_contract_class(class_hash)?;
            self.class_hash_to_class.insert(*class_hash, contract_class);
        }

        let contract_class = self
            .class_hash_to_class
            .get(class_hash)
            .expect("The class hash must appear in the cache.");
        Ok(contract_class.clone())
    }

    fn get_compiled_class_hash(&mut self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        if self.cache.get_compiled_class_hash(class_hash).is_none() {
            let compiled_class_hash = self.state.get_compiled_class_hash(class_hash)?;
            self.cache.set_compiled_class_hash_initial_value(class_hash, compiled_class_hash);
        }

        let compiled_class_hash = self
            .cache
            .get_compiled_class_hash(class_hash)
            .unwrap_or_else(|| panic!("Cannot retrieve '{class_hash:?}' from the cache."));
        Ok(*compiled_class_hash)
    }
}

impl<S: StateReader> State for CachedState<S> {
    fn set_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) {
        self.cache.set_storage_value(contract_address, key, value);
    }

    fn increment_nonce(&mut self, contract_address: ContractAddress) -> StateResult<()> {
        let current_nonce = self.get_nonce_at(contract_address)?;
        let current_nonce_as_u64 = usize::try_from(current_nonce.0)? as u64;
        let next_nonce_val = 1_u64 + current_nonce_as_u64;
        let next_nonce = Nonce(StarkFelt::from(next_nonce_val));
        self.cache.set_nonce_value(contract_address, next_nonce);

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

        self.cache.set_class_hash_write(contract_address, class_hash);
        Ok(())
    }

    fn set_contract_class(
        &mut self,
        class_hash: &ClassHash,
        contract_class: ContractClass,
    ) -> StateResult<()> {
        self.class_hash_to_class.insert(*class_hash, contract_class);
        Ok(())
    }

    fn set_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
    ) -> StateResult<()> {
        self.cache.set_compiled_class_hash_write(class_hash, compiled_class_hash);
        Ok(())
    }

    // Assumes calling to `count_actual_state_changes` before. See its documentation.
    fn to_state_diff(&self) -> CommitmentStateDiff {
        type StorageDiff = IndexMap<ContractAddress, IndexMap<StorageKey, StarkFelt>>;

        let state_cache = &self.cache;
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
impl Default for CachedState<crate::test_utils::DictStateReader> {
    fn default() -> Self {
        Self {
            state: Default::default(),
            cache: Default::default(),
            class_hash_to_class: Default::default(),
        }
    }
}

pub type ContractStorageKey = (ContractAddress, StorageKey);

#[derive(IntoIterator, Debug, Default)]
pub struct StorageView(pub HashMap<ContractStorageKey, StarkFelt>);

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
/// The tracked changes are needed for block state commitment.

// Invariant: keys cannot be deleted from fields (only used internally by the cached state).
#[derive(Debug, Default, PartialEq)]
struct StateCache {
    // Reader's cached information; initial values, read before any write operation (per cell).
    nonce_initial_values: HashMap<ContractAddress, Nonce>,
    class_hash_initial_values: HashMap<ContractAddress, ClassHash>,
    storage_initial_values: HashMap<ContractStorageKey, StarkFelt>,
    compiled_class_hash_initial_values: HashMap<ClassHash, CompiledClassHash>,

    // Writer's cached information.
    nonce_writes: HashMap<ContractAddress, Nonce>,
    class_hash_writes: HashMap<ContractAddress, ClassHash>,
    storage_writes: HashMap<ContractStorageKey, StarkFelt>,
    compiled_class_hash_writes: HashMap<ClassHash, CompiledClassHash>,
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

    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> Option<&CompiledClassHash> {
        self.compiled_class_hash_writes
            .get(&class_hash)
            .or_else(|| self.compiled_class_hash_initial_values.get(&class_hash))
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

    fn get_storage_updates(&self) -> HashMap<ContractStorageKey, StarkFelt> {
        subtract_mappings(&self.storage_writes, &self.storage_initial_values)
    }

    fn get_class_hash_updates(&self) -> HashMap<ContractAddress, ClassHash> {
        subtract_mappings(&self.class_hash_writes, &self.class_hash_initial_values)
    }

    fn get_nonce_updates(&self) -> HashMap<ContractAddress, Nonce> {
        subtract_mappings(&self.nonce_writes, &self.nonce_initial_values)
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
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        self.0.get_storage_at(contract_address, key)
    }

    fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce> {
        self.0.get_nonce_at(contract_address)
    }

    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        self.0.get_class_hash_at(contract_address)
    }

    fn get_compiled_contract_class(
        &mut self,
        class_hash: &ClassHash,
    ) -> StateResult<ContractClass> {
        self.0.get_compiled_contract_class(class_hash)
    }

    fn get_compiled_class_hash(&mut self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        self.0.get_compiled_class_hash(class_hash)
    }
}

impl<'a, S: State + ?Sized> State for MutRefState<'a, S> {
    fn set_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) {
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
        class_hash: &ClassHash,
        contract_class: ContractClass,
    ) -> StateResult<()> {
        self.0.set_contract_class(class_hash, contract_class)
    }

    fn to_state_diff(&self) -> CommitmentStateDiff {
        self.0.to_state_diff()
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

/// Adds the ability to perform a transactional execution.
impl<'a, S: StateReader> TransactionalState<'a, S> {
    /// Commits changes in the child (wrapping) state to its parent.
    pub fn commit(self) {
        let child_cache = self.cache;
        let parent_cache = &mut self.state.0.cache;

        parent_cache.nonce_writes.extend(child_cache.nonce_writes);
        parent_cache.class_hash_writes.extend(child_cache.class_hash_writes);
        parent_cache.storage_writes.extend(child_cache.storage_writes);
        parent_cache.compiled_class_hash_writes.extend(child_cache.compiled_class_hash_writes);
        self.state.0.class_hash_to_class.extend(self.class_hash_to_class);
    }

    /// Drops `self`.
    pub fn abort(self) {}
}

/// Holds uncommitted changes induced on StarkNet contracts.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CommitmentStateDiff {
    // Contract instance attributes (per address).
    pub address_to_class_hash: IndexMap<ContractAddress, ClassHash>,
    pub address_to_nonce: IndexMap<ContractAddress, Nonce>,
    pub storage_updates: IndexMap<ContractAddress, IndexMap<StorageKey, StarkFelt>>,

    // Global attributes.
    pub class_hash_to_compiled_class_hash: IndexMap<ClassHash, CompiledClassHash>,
}

/// Holds the number of state changes.
#[derive(Debug, Eq, PartialEq)]
pub struct StateChanges {
    pub n_storage_updates: usize,
    pub n_class_hash_updates: usize,
    pub n_nonce_updates: usize,
    pub n_modified_contracts: usize,
}
