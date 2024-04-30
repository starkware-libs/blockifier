use std::collections::{HashMap, HashSet};

use cairo_vm::serde::deserialize_program::BuiltinName;
use cairo_vm::vm::runners::builtin_runner::HASH_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use serde::Deserialize;
use starknet_api::core::ClassHash;

use crate::blockifier::transaction_executor::{
    TransactionExecutorError, TransactionExecutorResult,
};
use crate::execution::call_info::ExecutionSummary;
use crate::fee::gas_usage::get_onchain_data_segment_length;
use crate::state::cached_state::{StateChangesKeys, StorageEntry, TransactionalState};
use crate::state::state_api::StateReader;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{ExecutionResourcesTraits, TransactionResources};

#[cfg(test)]
#[path = "bouncer_test.rs"]
mod test;

macro_rules! impl_checked_sub {
    ($($field:ident),+) => {
        pub fn checked_sub(self: Self, other: Self) -> Option<Self> {
            Some(
                Self {
                    $(
                        $field: self.$field.checked_sub(other.$field)?,
                    )+
                }
            )
        }
    };
}

pub type HashMapWrapper = HashMap<String, usize>;

#[derive(Debug, Default, PartialEq, Clone)]
pub struct BouncerConfig {
    pub block_max_capacity: BouncerWeights,
    pub block_max_capacity_with_keccak: BouncerWeights,
}

impl BouncerConfig {
    pub fn max() -> Self {
        Self {
            block_max_capacity_with_keccak: BouncerWeights::max(true),
            block_max_capacity: BouncerWeights::max(false),
        }
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    derive_more::Add,
    derive_more::AddAssign,
    derive_more::Sub,
    Deserialize,
    PartialEq,
)]
/// Represents the execution resources counted throughout block creation.
pub struct BouncerWeights {
    pub builtin_count: BuiltinCount,
    pub gas: usize,
    pub message_segment_length: usize,
    pub n_events: usize,
    pub n_steps: usize,
    pub state_diff_size: usize,
}

impl BouncerWeights {
    impl_checked_sub!(
        builtin_count,
        gas,
        message_segment_length,
        n_events,
        n_steps,
        state_diff_size
    );

    pub fn has_room(&self, other: Self) -> bool {
        self.checked_sub(other).is_some()
    }

    pub fn max(with_keccak: bool) -> Self {
        Self {
            gas: usize::MAX,
            n_steps: usize::MAX,
            message_segment_length: usize::MAX,
            state_diff_size: usize::MAX,
            n_events: usize::MAX,
            builtin_count: BuiltinCount::max(with_keccak),
        }
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    derive_more::Add,
    derive_more::AddAssign,
    derive_more::Sub,
    Deserialize,
    PartialEq,
)]
pub struct BuiltinCount {
    pub bitwise: usize,
    pub ecdsa: usize,
    pub ec_op: usize,
    pub keccak: usize,
    pub pedersen: usize,
    pub poseidon: usize,
    pub range_check: usize,
}

impl BuiltinCount {
    impl_checked_sub!(bitwise, ecdsa, ec_op, keccak, pedersen, poseidon, range_check);

    pub fn max(with_keccak: bool) -> Self {
        let keccak = if with_keccak { usize::MAX } else { 0 };
        Self {
            bitwise: usize::MAX,
            ecdsa: usize::MAX,
            ec_op: usize::MAX,
            keccak,
            pedersen: usize::MAX,
            poseidon: usize::MAX,
            range_check: usize::MAX,
        }
    }
}

impl From<HashMapWrapper> for BuiltinCount {
    fn from(mut data: HashMapWrapper) -> Self {
        // TODO(yael 24/3/24): replace the unwrap_or_default with expect, once the
        // ExecutionResources contains all the builtins.
        // The keccak config we get from python is not always present.
        let builtin_count = Self {
            bitwise: data.remove(BuiltinName::bitwise.name()).unwrap_or_default(),
            ecdsa: data.remove(BuiltinName::ecdsa.name()).unwrap_or_default(),
            ec_op: data.remove(BuiltinName::ec_op.name()).unwrap_or_default(),
            keccak: data.remove(BuiltinName::keccak.name()).unwrap_or_default(),
            pedersen: data.remove(BuiltinName::pedersen.name()).unwrap_or_default(),
            poseidon: data.remove(BuiltinName::poseidon.name()).unwrap_or_default(),
            range_check: data.remove(BuiltinName::range_check.name()).unwrap_or_default(),
        };
        assert!(
            data.is_empty(),
            "The following keys do not exist in BuiltinCount: {:?} ",
            data.keys()
        );
        builtin_count
    }
}

#[derive(Debug, Default, PartialEq)]
#[cfg_attr(test, derive(Clone))]
pub struct Bouncer {
    // Additional info; maintained and used to calculate the residual contribution of a transaction
    // to the accumulated weights.
    pub executed_class_hashes: HashSet<ClassHash>,
    pub visited_storage_entries: HashSet<StorageEntry>,
    pub state_changes_keys: StateChangesKeys,

    pub bouncer_config: BouncerConfig,

    accumulated_weights: BouncerWeights,
}

impl Bouncer {
    pub fn new(bouncer_config: BouncerConfig) -> Self {
        Bouncer { bouncer_config, ..Default::default() }
    }

    pub fn get_accumulated_weights(&self) -> &BouncerWeights {
        &self.accumulated_weights
    }

    fn _update(
        &mut self,
        tx_weights: BouncerWeights,
        tx_execution_summary: &ExecutionSummary,
        state_changes_keys: &StateChangesKeys,
    ) {
        self.accumulated_weights += tx_weights;
        self.visited_storage_entries.extend(&tx_execution_summary.visited_storage_entries);
        self.executed_class_hashes.extend(&tx_execution_summary.executed_class_hashes);
        // Note: cancelling writes (0 -> 1 -> 0) will not be removed, but it's fine since fee was
        // charged for them.
        self.state_changes_keys.extend(state_changes_keys);
    }

    /// Updates the bouncer with a new transaction.
    pub fn try_update<S: StateReader>(
        &mut self,
        state: &mut TransactionalState<'_, S>,
        tx_execution_summary: &ExecutionSummary,
        tx_resources: &TransactionResources,
    ) -> TransactionExecutorResult<()> {
        // The countings here should be linear in the transactional state changes and execution info
        // rather than the cumulative state attributes.
        let state_changes_keys = self.get_state_changes_keys(state)?;
        let tx_weights =
            self.get_tx_weights(state, tx_execution_summary, tx_resources, &state_changes_keys)?;

        let mut max_capacity = self.bouncer_config.block_max_capacity;
        if self.accumulated_weights.builtin_count.keccak > 0 || tx_weights.builtin_count.keccak > 0
        {
            max_capacity = self.bouncer_config.block_max_capacity_with_keccak;
        }

        // Check if the transaction is too large to fit any block.
        if !max_capacity.has_room(tx_weights) {
            Err(TransactionExecutionError::TransactionTooLarge)?
        }

        // Check if the transaction can fit the current block available capacity.
        if !max_capacity.has_room(self.accumulated_weights + tx_weights) {
            Err(TransactionExecutorError::BlockFull)?
        }

        self._update(tx_weights, tx_execution_summary, &state_changes_keys);

        Ok(())
    }

    pub fn get_tx_weights<S: StateReader>(
        &mut self,
        state: &mut TransactionalState<'_, S>,
        tx_execution_summary: &ExecutionSummary,
        tx_resources: &TransactionResources,
        state_changes_keys: &StateChangesKeys,
    ) -> TransactionExecutorResult<BouncerWeights> {
        let (message_segment_length, gas_usage) =
            tx_resources.starknet_resources.calculate_message_l1_resources();

        let mut additional_os_resources = get_casm_hash_calculation_resources(
            state,
            &self.executed_class_hashes,
            &tx_execution_summary.executed_class_hashes,
        )?;
        additional_os_resources += &get_particia_update_resources(
            &self.visited_storage_entries,
            &tx_execution_summary.visited_storage_entries,
        );

        let vm_resources = &additional_os_resources + &tx_resources.vm_resources;

        Ok(BouncerWeights {
            gas: gas_usage,
            message_segment_length,
            n_events: tx_resources.starknet_resources.n_events,
            n_steps: vm_resources.total_n_steps(),
            builtin_count: BuiltinCount::from(vm_resources.prover_builtins()),
            state_diff_size: get_onchain_data_segment_length(&state_changes_keys.count()),
        })
    }

    pub fn get_state_changes_keys<S: StateReader>(
        &self,
        state: &mut TransactionalState<'_, S>,
    ) -> TransactionExecutorResult<StateChangesKeys> {
        let tx_state_changes_keys = state.get_actual_state_changes()?.into_keys();
        Ok(tx_state_changes_keys.difference(&self.state_changes_keys))
    }

    #[cfg(test)]
    pub fn set_accumulated_weights(&mut self, weights: BouncerWeights) {
        self.accumulated_weights = weights;
    }
}

/// Returns the estimated VM resources for Casm hash calculation (done by the OS), of the newly
/// executed classes by the current transaction.
pub fn get_casm_hash_calculation_resources<S: StateReader>(
    state: &mut TransactionalState<'_, S>,
    block_executed_class_hashes: &HashSet<ClassHash>,
    tx_executed_class_hashes: &HashSet<ClassHash>,
) -> TransactionExecutorResult<ExecutionResources> {
    let newly_executed_class_hashes: HashSet<&ClassHash> =
        tx_executed_class_hashes.difference(block_executed_class_hashes).collect();

    let mut casm_hash_computation_resources = ExecutionResources::default();

    for class_hash in newly_executed_class_hashes {
        let class = state.get_compiled_contract_class(*class_hash)?;
        casm_hash_computation_resources += &class.estimate_casm_hash_computation_resources();
    }

    Ok(casm_hash_computation_resources)
}

/// Returns the estimated VM resources for Patricia tree updates, or hash invocations
/// (done by the OS), required by the execution of the current transaction.
// For each tree: n_visited_leaves * log(n_initialized_leaves)
// as the height of a Patricia tree with N uniformly distributed leaves is ~log(N),
// and number of visited leaves includes reads and writes.
pub fn get_particia_update_resources(
    block_visited_storage_entries: &HashSet<StorageEntry>,
    tx_visited_storage_entries: &HashSet<StorageEntry>,
) -> ExecutionResources {
    let newly_visited_storage_entries: HashSet<&StorageEntry> =
        tx_visited_storage_entries.difference(block_visited_storage_entries).collect();
    let n_newly_visited_leaves = newly_visited_storage_entries.len();

    const TREE_HEIGHT_UPPER_BOUND: usize = 24;
    let n_updates = n_newly_visited_leaves * TREE_HEIGHT_UPPER_BOUND;

    ExecutionResources {
        // TODO(Yoni, 1/5/2024): re-estimate this.
        n_steps: 32 * n_updates,
        // For each Patricia update there are two hash calculations.
        builtin_instance_counter: HashMap::from([(HASH_BUILTIN_NAME.to_string(), 2 * n_updates)]),
        n_memory_holes: 0,
    }
}
