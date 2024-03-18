use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use derive_more::IntoIterator;
use indexmap::IndexMap;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::abi::abi_utils::get_fee_token_var_address;
use crate::execution::contract_class::ContractClass;
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader, StateResult};
use crate::utils::{strict_subtract_mappings, subtract_mappings};

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
    // Using interior mutability to update caches during `State`'s immutable getters.
    pub(crate) cache: RefCell<StateCache>,
    pub(crate) class_hash_to_class: RefCell<ContractClassMapping>,
    /// A map from class hash to the set of PC values that were visited in the class.
    pub visited_pcs: HashMap<ClassHash, HashSet<usize>>,
}

impl<S: StateReader> CachedState<S> {
    pub fn new(state: S) -> Self {
        Self {
            state,
            cache: RefCell::new(StateCache::default()),
            class_hash_to_class: RefCell::new(HashMap::default()),
            visited_pcs: HashMap::default(),
        }
    }

    /// Creates a transactional instance from the given cached state.
    /// It allows performing buffered modifying actions on the given state, which
    /// will either all happen (will be committed) or none of them (will be discarded).
    pub fn create_transactional(state: &mut CachedState<S>) -> TransactionalState<'_, S> {
        CachedState::new(MutRefState::new(state))
    }

    /// Returns the storage changes done through this state.
    /// For each contract instance (address) we have three attributes: (class hash, nonce, storage
    /// root); the state updates correspond to them.
    pub fn get_actual_state_changes(&mut self) -> StateResult<StateChanges> {
        self.update_initial_values_of_write_only_access()?;
        let cache = self.cache.borrow();

        Ok(StateChanges {
            storage_updates: cache.get_storage_updates(),
            nonce_updates: cache.get_nonce_updates(),
            // Class hash updates (deployed contracts + replace_class syscall).
            class_hash_updates: cache.get_class_hash_updates(),
            // Compiled class hash updates (declare Cairo 1 contract).
            compiled_class_hash_updates: cache.get_compiled_class_hash_updates(),
        })
    }

    pub fn update_cache(&mut self, write_updates: StateMaps) {
        let mut cache = self.cache.borrow_mut();
        cache.writes.extend(&write_updates);
    }

    pub fn update_contract_class_cache(
        &mut self,
        local_contract_cache_updates: ContractClassMapping,
    ) {
        self.class_hash_to_class.get_mut().extend(local_contract_cache_updates);
    }

    pub fn update_visited_pcs_cache(&mut self, visited_pcs: &HashMap<ClassHash, HashSet<usize>>) {
        for (class_hash, class_visited_pcs) in visited_pcs {
            self.add_visited_pcs(*class_hash, class_visited_pcs);
        }
    }

    /// Updates cache with initial cell values for write-only access.
    /// If written values match the original, the cell is unchanged and not counted as a
    /// storage-change for fee calculation.
    /// Same for class hash and nonce writes.
    // TODO(Noa, 30/07/23): Consider adding DB getters in bulk (via a DB read transaction).
    fn update_initial_values_of_write_only_access(&mut self) -> StateResult<()> {
        let cache = &mut *self.cache.borrow_mut();

        // Eliminate storage writes that are identical to the initial value (no change). Assumes
        // that `set_storage_at` does not affect the state field.
        for contract_storage_key in cache.writes.storage.keys() {
            if !cache.initial_reads.storage.contains_key(contract_storage_key) {
                // First access to this cell was write; cache initial value.
                cache.initial_reads.storage.insert(
                    *contract_storage_key,
                    self.state.get_storage_at(contract_storage_key.0, contract_storage_key.1)?,
                );
            }
        }

        for contract_address in cache.writes.class_hashes.keys() {
            if !cache.initial_reads.class_hashes.contains_key(contract_address) {
                // First access to this cell was write; cache initial value.
                cache
                    .initial_reads
                    .class_hashes
                    .insert(*contract_address, self.state.get_class_hash_at(*contract_address)?);
            }
        }

        for contract_address in cache.writes.nonces.keys() {
            if !cache.initial_reads.nonces.contains_key(contract_address) {
                // First access to this cell was write; cache initial value.
                cache
                    .initial_reads
                    .nonces
                    .insert(*contract_address, self.state.get_nonce_at(*contract_address)?);
            }
        }

        Ok(())
    }

    pub fn to_state_diff(&mut self) -> CommitmentStateDiff {
        type StorageDiff = IndexMap<ContractAddress, IndexMap<StorageKey, StarkFelt>>;

        // TODO(Gilad): Consider returning an error here, would require changing the API though.
        self.update_initial_values_of_write_only_access()
            .unwrap_or_else(|_| panic!("Cannot convert stateDiff to CommitmentStateDiff."));

        let state_cache = self.cache.borrow();
        let class_hash_updates = state_cache.get_class_hash_updates();
        let storage_diffs = state_cache.get_storage_updates();
        let nonces = state_cache.get_nonce_updates();
        let declared_classes = state_cache.writes.compiled_class_hashes.clone();

        CommitmentStateDiff {
            address_to_class_hash: IndexMap::from_iter(class_hash_updates),
            storage_updates: StorageDiff::from(StorageView(storage_diffs)),
            class_hash_to_compiled_class_hash: IndexMap::from_iter(declared_classes),
            address_to_nonce: IndexMap::from_iter(nonces),
        }
    }
}

#[cfg(any(feature = "testing", test))]
impl<S: StateReader> From<S> for CachedState<S> {
    fn from(state_reader: S) -> Self {
        CachedState::new(state_reader)
    }
}

impl<S: StateReader> StateReader for CachedState<S> {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        let mut cache = self.cache.borrow_mut();

        if cache.get_storage_at(contract_address, key).is_none() {
            let storage_value = self.state.get_storage_at(contract_address, key)?;
            cache.set_storage_initial_value(contract_address, key, storage_value);
        }

        let value = cache.get_storage_at(contract_address, key).unwrap_or_else(|| {
            panic!("Cannot retrieve '{contract_address:?}' and '{key:?}' from the cache.")
        });
        Ok(*value)
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        let mut cache = self.cache.borrow_mut();

        if cache.get_nonce_at(contract_address).is_none() {
            let nonce = self.state.get_nonce_at(contract_address)?;
            cache.set_nonce_initial_value(contract_address, nonce);
        }

        let nonce = cache
            .get_nonce_at(contract_address)
            .unwrap_or_else(|| panic!("Cannot retrieve '{contract_address:?}' from the cache."));

        Ok(*nonce)
    }

    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        let mut cache = self.cache.borrow_mut();

        if cache.get_class_hash_at(contract_address).is_none() {
            let class_hash = self.state.get_class_hash_at(contract_address)?;
            cache.set_class_hash_initial_value(contract_address, class_hash);
        }

        let class_hash = cache
            .get_class_hash_at(contract_address)
            .unwrap_or_else(|| panic!("Cannot retrieve '{contract_address:?}' from the cache."));
        Ok(*class_hash)
    }

    fn get_compiled_contract_class(&self, class_hash: ClassHash) -> StateResult<ContractClass> {
        let mut cache = self.cache.borrow_mut();
        let class_hash_to_class = &mut *self.class_hash_to_class.borrow_mut();

        if let std::collections::hash_map::Entry::Vacant(vacant_entry) =
            class_hash_to_class.entry(class_hash)
        {
            match self.state.get_compiled_contract_class(class_hash) {
                Err(StateError::UndeclaredClassHash(class_hash)) => {
                    cache.set_declared_contract_initial_values(class_hash, false);
                    Err(StateError::UndeclaredClassHash(class_hash))?;
                }
                Err(error) => Err(error)?,
                Ok(contract_class) => {
                    cache.set_declared_contract_initial_values(class_hash, true);
                    vacant_entry.insert(contract_class);
                }
            }
        }

        let contract_class = class_hash_to_class
            .get(&class_hash)
            .cloned()
            .expect("The class hash must appear in the cache.");

        Ok(contract_class)
    }

    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        let mut cache = self.cache.borrow_mut();

        if cache.get_compiled_class_hash(class_hash).is_none() {
            let compiled_class_hash = self.state.get_compiled_class_hash(class_hash)?;
            cache.set_compiled_class_hash_initial_value(class_hash, compiled_class_hash);
        }

        let compiled_class_hash = cache
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
    ) -> StateResult<()> {
        self.cache.get_mut().set_storage_value(contract_address, key, value);

        Ok(())
    }

    fn increment_nonce(&mut self, contract_address: ContractAddress) -> StateResult<()> {
        let current_nonce = self.get_nonce_at(contract_address)?;
        // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion
        // works.
        let current_nonce_as_u64: u64 =
            usize::try_from(current_nonce.0)?.try_into().expect("Failed to convert usize to u64.");
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
        self.class_hash_to_class.get_mut().insert(class_hash, contract_class);
        let mut cache = self.cache.borrow_mut();
        cache.declare_contract(class_hash);
        Ok(())
    }

    fn set_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
    ) -> StateResult<()> {
        self.cache.get_mut().set_compiled_class_hash_write(class_hash, compiled_class_hash);
        Ok(())
    }

    fn add_visited_pcs(&mut self, class_hash: ClassHash, pcs: &HashSet<usize>) {
        self.visited_pcs.entry(class_hash).or_default().extend(pcs);
    }
}

#[cfg(any(feature = "testing", test))]
impl Default for CachedState<crate::test_utils::dict_state_reader::DictStateReader> {
    fn default() -> Self {
        Self {
            state: Default::default(),
            cache: Default::default(),
            class_hash_to_class: Default::default(),
            visited_pcs: Default::default(),
        }
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

#[derive(Debug, Default, PartialEq, Eq)]
pub struct StateMaps {
    pub(crate) nonces: HashMap<ContractAddress, Nonce>,
    pub(crate) class_hashes: HashMap<ContractAddress, ClassHash>,
    pub(crate) storage: HashMap<StorageEntry, StarkFelt>,
    pub(crate) compiled_class_hashes: HashMap<ClassHash, CompiledClassHash>,
    pub(crate) declared_contracts: HashMap<ClassHash, bool>,
}

impl StateMaps {
    pub fn extend(&mut self, other: &Self) {
        self.nonces.extend(&other.nonces);
        self.class_hashes.extend(&other.class_hashes);
        self.storage.extend(&other.storage);
        self.compiled_class_hashes.extend(&other.compiled_class_hashes);
        self.declared_contracts.extend(&other.declared_contracts)
    }
}
/// Caches read and write requests.
/// The tracked changes are needed for block state commitment.

// Invariant: keys cannot be deleted from fields (only used internally by the cached state).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StateCache {
    // Reader's cached information; initial values, read before any write operation (per cell).
    pub(crate) initial_reads: StateMaps,

    // Writer's cached information.
    pub(crate) writes: StateMaps,
}

impl StateCache {
    fn declare_contract(&mut self, class_hash: ClassHash) {
        self.writes.declared_contracts.insert(class_hash, true);
    }

    fn set_declared_contract_initial_values(&mut self, class_hash: ClassHash, is_declared: bool) {
        self.initial_reads.declared_contracts.insert(class_hash, is_declared);
    }

    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> Option<&StarkFelt> {
        let contract_storage_key = (contract_address, key);
        self.writes
            .storage
            .get(&contract_storage_key)
            .or_else(|| self.initial_reads.storage.get(&contract_storage_key))
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> Option<&Nonce> {
        self.writes
            .nonces
            .get(&contract_address)
            .or_else(|| self.initial_reads.nonces.get(&contract_address))
    }

    pub fn set_storage_initial_value(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) {
        let contract_storage_key = (contract_address, key);
        self.initial_reads.storage.insert(contract_storage_key, value);
    }

    fn set_storage_value(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) {
        let contract_storage_key = (contract_address, key);
        self.writes.storage.insert(contract_storage_key, value);
    }

    fn set_nonce_initial_value(&mut self, contract_address: ContractAddress, nonce: Nonce) {
        self.initial_reads.nonces.insert(contract_address, nonce);
    }

    fn set_nonce_value(&mut self, contract_address: ContractAddress, nonce: Nonce) {
        self.writes.nonces.insert(contract_address, nonce);
    }

    fn get_class_hash_at(&self, contract_address: ContractAddress) -> Option<&ClassHash> {
        self.writes
            .class_hashes
            .get(&contract_address)
            .or_else(|| self.initial_reads.class_hashes.get(&contract_address))
    }

    fn set_class_hash_initial_value(
        &mut self,
        contract_address: ContractAddress,
        class_hash: ClassHash,
    ) {
        self.initial_reads.class_hashes.insert(contract_address, class_hash);
    }

    fn set_class_hash_write(&mut self, contract_address: ContractAddress, class_hash: ClassHash) {
        self.writes.class_hashes.insert(contract_address, class_hash);
    }

    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> Option<&CompiledClassHash> {
        self.writes
            .compiled_class_hashes
            .get(&class_hash)
            .or_else(|| self.initial_reads.compiled_class_hashes.get(&class_hash))
    }

    fn set_compiled_class_hash_initial_value(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
    ) {
        self.initial_reads.compiled_class_hashes.insert(class_hash, compiled_class_hash);
    }

    fn set_compiled_class_hash_write(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
    ) {
        self.writes.compiled_class_hashes.insert(class_hash, compiled_class_hash);
    }

    fn get_storage_updates(&self) -> HashMap<StorageEntry, StarkFelt> {
        strict_subtract_mappings(&self.writes.storage, &self.initial_reads.storage)
    }

    fn get_class_hash_updates(&self) -> HashMap<ContractAddress, ClassHash> {
        strict_subtract_mappings(&self.writes.class_hashes, &self.initial_reads.class_hashes)
    }

    fn get_nonce_updates(&self) -> HashMap<ContractAddress, Nonce> {
        strict_subtract_mappings(&self.writes.nonces, &self.initial_reads.nonces)
    }

    fn get_compiled_class_hash_updates(&self) -> HashMap<ClassHash, CompiledClassHash> {
        // This is not a strict subtraction, as Papyrus does not support the
        // `get_compiled_class_hash` method. When declaring a Cairo 1 class we update the
        // writes mapping but cannot update the reads mapping. As a result, the compiled
        // class hash writes keys are not a subset of compiled class hash initial values keys.

        subtract_mappings(
            &self.writes.compiled_class_hashes,
            &self.initial_reads.compiled_class_hashes,
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

pub type TransactionalState<'a, S> = CachedState<MutRefState<'a, CachedState<S>>>;

/// Adds the ability to perform a transactional execution.
impl<'a, S: StateReader> TransactionalState<'a, S> {
    /// Commits changes in the child (wrapping) state to its parent.
    pub fn commit(self) {
        let state = self.state.0;
        let child_cache = self.cache.into_inner();
        state.update_cache(child_cache.writes);
        state.update_contract_class_cache(self.class_hash_to_class.into_inner());
        state.update_visited_pcs_cache(&self.visited_pcs);
    }

    /// Drops `self`.
    pub fn abort(self) {}
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

/// Used to track the state diff size, which is determined by the number of new keys.
/// Also, can be used to accuratly measure the contribution of a single (say, transactional)
/// state to a cumulative state diff - provides set-like functionallities for this porpuse.
///
/// Note: Cancelling writes (0 -> 1 -> 0) are neglected here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StateChangesKeys {
    nonce_keys: HashSet<ContractAddress>,
    class_hash_keys: HashSet<ContractAddress>,
    storage_keys: HashSet<StorageEntry>,
    compiled_class_hash_keys: HashSet<ClassHash>,
    // Note: this field may not be consistent with the above keys; specifically, it may be
    // strictlly contained in them. For example, as a result of a `difference` operation.
    modified_contracts: HashSet<ContractAddress>,
}

impl StateChangesKeys {
    // For each set member, collects the values that are in `self` but not in `other`.
    // The output represents the residual contribution of `self` to `other`'s corresponding
    // state diff.
    pub fn difference(&self, other: &Self) -> Self {
        Self {
            nonce_keys: self.nonce_keys.difference(&other.nonce_keys).cloned().collect(),
            class_hash_keys: self
                .class_hash_keys
                .difference(&other.class_hash_keys)
                .cloned()
                .collect(),
            storage_keys: self.storage_keys.difference(&other.storage_keys).cloned().collect(),
            compiled_class_hash_keys: self
                .compiled_class_hash_keys
                .difference(&other.compiled_class_hash_keys)
                .cloned()
                .collect(),
            modified_contracts: self
                .modified_contracts
                .difference(&other.modified_contracts)
                .cloned()
                .collect(),
        }
    }

    pub fn extend(&mut self, other: &Self) {
        self.nonce_keys.extend(&other.nonce_keys);
        self.class_hash_keys.extend(&other.class_hash_keys);
        self.storage_keys.extend(&other.storage_keys);
        self.compiled_class_hash_keys.extend(&other.compiled_class_hash_keys);
        self.modified_contracts.extend(&other.modified_contracts);
    }

    pub fn count(&self) -> StateChangesCount {
        // nonce_keys effect is captured by modified_contracts; it is not used but kept for
        // completeness of this struct.
        StateChangesCount {
            n_storage_updates: self.storage_keys.len(),
            n_class_hash_updates: self.class_hash_keys.len(),
            n_compiled_class_hash_updates: self.compiled_class_hash_keys.len(),
            n_modified_contracts: self.modified_contracts.len(),
        }
    }

    #[cfg(any(feature = "testing", test))]
    pub fn create_for_testing(nonce_keys: HashSet<ContractAddress>) -> Self {
        Self { nonce_keys, ..Default::default() }
    }
}

/// Holds the state changes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StateChanges {
    pub storage_updates: HashMap<StorageEntry, StarkFelt>,
    pub nonce_updates: HashMap<ContractAddress, Nonce>,
    pub class_hash_updates: HashMap<ContractAddress, ClassHash>,
    pub compiled_class_hash_updates: HashMap<ClassHash, CompiledClassHash>,
}

impl StateChanges {
    /// Merges the given state changes into a single one. Note that the order of the state changes
    /// is important. The state changes are merged in the order they appear in the given vector.
    pub fn merge(state_changes: Vec<Self>) -> Self {
        let mut merged_state_changes = Self::default();
        for state_change in state_changes {
            merged_state_changes.storage_updates.extend(state_change.storage_updates);
            merged_state_changes.nonce_updates.extend(state_change.nonce_updates);
            merged_state_changes.class_hash_updates.extend(state_change.class_hash_updates);
            merged_state_changes
                .compiled_class_hash_updates
                .extend(state_change.compiled_class_hash_updates);
        }

        merged_state_changes
    }

    pub fn get_modified_contracts(&self) -> HashSet<ContractAddress> {
        // Storage updates.
        let mut modified_contracts: HashSet<ContractAddress> =
            self.storage_updates.keys().map(|address_key_pair| address_key_pair.0).collect();
        // Nonce updates.
        modified_contracts.extend(self.nonce_updates.keys());
        // Class hash updates (deployed contracts + replace_class syscall).
        modified_contracts.extend(self.class_hash_updates.keys());

        modified_contracts
    }

    pub fn count_for_fee_charge(
        &self,
        sender_address: Option<ContractAddress>,
        fee_token_address: ContractAddress,
    ) -> StateChangesCount {
        let mut modified_contracts = self.get_modified_contracts();

        // For account transactions, we need to compute the transaction fee before we can execute
        // the fee transfer, and the fee should cover the state changes that happen in the
        // fee transfer. The fee transfer is going to update the balance of the sequencer
        // and the balance of the sender contract, but we don't charge the sender for the
        // sequencer balance change as it is amortized across the block.
        let mut n_storage_updates = self.storage_updates.len();
        if let Some(sender_address) = sender_address {
            let sender_balance_key = get_fee_token_var_address(sender_address);
            if !self.storage_updates.contains_key(&(fee_token_address, sender_balance_key)) {
                n_storage_updates += 1;
            }
        }

        // Exclude the fee token contract modification, since it’s charged once throughout the
        // block.
        modified_contracts.remove(&fee_token_address);

        StateChangesCount {
            n_storage_updates,
            n_class_hash_updates: self.class_hash_updates.len(),
            n_compiled_class_hash_updates: self.compiled_class_hash_updates.len(),
            n_modified_contracts: modified_contracts.len(),
        }
    }

    pub fn into_keys(self) -> StateChangesKeys {
        StateChangesKeys {
            modified_contracts: self.get_modified_contracts(),
            nonce_keys: self.nonce_updates.into_keys().collect(),
            class_hash_keys: self.class_hash_updates.into_keys().collect(),
            storage_keys: self.storage_updates.into_keys().collect(),
            compiled_class_hash_keys: self.compiled_class_hash_updates.into_keys().collect(),
        }
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
