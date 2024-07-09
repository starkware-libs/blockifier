use std::collections::{HashMap, HashSet};

use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use serde::{Deserialize, Serialize};
use starknet_api::core::ClassHash;

use crate::blockifier::transaction_executor::{
    TransactionExecutorError, TransactionExecutorResult,
};
use crate::execution::call_info::ExecutionSummary;
use crate::fee::gas_usage::get_onchain_data_segment_length;
use crate::state::cached_state::{StateChangesKeys, StorageEntry};
use crate::state::state_api::StateReader;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{
    ExecutionResourcesTraits, TransactionExecutionResult, TransactionResources,
};

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

pub type HashMapWrapper = HashMap<BuiltinName, usize>;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BouncerConfig {
    pub block_max_capacity: BouncerWeights,
}

impl BouncerConfig {
    pub fn max() -> Self {
        Self { block_max_capacity: BouncerWeights::max() }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn has_room(&self, weights: BouncerWeights) -> bool {
        self.block_max_capacity.has_room(weights)
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
    Serialize,
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

    pub fn max() -> Self {
        Self {
            gas: usize::MAX,
            n_steps: usize::MAX,
            message_segment_length: usize::MAX,
            state_diff_size: usize::MAX,
            n_events: usize::MAX,
            builtin_count: BuiltinCount::max(),
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
    Serialize,
)]
pub struct BuiltinCount {
    pub add_mod: usize,
    pub bitwise: usize,
    pub ecdsa: usize,
    pub ec_op: usize,
    pub keccak: usize,
    pub mul_mod: usize,
    pub pedersen: usize,
    pub poseidon: usize,
    pub range_check: usize,
    pub range_check96: usize,
}

macro_rules! impl_all_non_zero {
    ($($field:ident),+) => {
        pub fn all_non_zero(&self) -> bool {
            $( self.$field != 0 )&&+
        }
    };
}

macro_rules! impl_builtin_variants {
    ($($field:ident),+) => {
        impl_checked_sub!($($field),+);
        impl_all_non_zero!($($field),+);
    };
}

impl BuiltinCount {
    impl_builtin_variants!(
        add_mod,
        bitwise,
        ec_op,
        ecdsa,
        keccak,
        mul_mod,
        pedersen,
        poseidon,
        range_check,
        range_check96
    );

    pub fn max() -> Self {
        Self {
            add_mod: usize::MAX,
            bitwise: usize::MAX,
            ecdsa: usize::MAX,
            ec_op: usize::MAX,
            keccak: usize::MAX,
            mul_mod: usize::MAX,
            pedersen: usize::MAX,
            poseidon: usize::MAX,
            range_check: usize::MAX,
            range_check96: usize::MAX,
        }
    }
}

impl From<HashMapWrapper> for BuiltinCount {
    fn from(mut data: HashMapWrapper) -> Self {
        // TODO(yael 24/3/24): replace the unwrap_or_default with expect, once the
        // ExecutionResources contains all the builtins.
        // The keccak config we get from python is not always present.
        let builtin_count = Self {
            add_mod: data.remove(&BuiltinName::add_mod).unwrap_or_default(),
            bitwise: data.remove(&BuiltinName::bitwise).unwrap_or_default(),
            ecdsa: data.remove(&BuiltinName::ecdsa).unwrap_or_default(),
            ec_op: data.remove(&BuiltinName::ec_op).unwrap_or_default(),
            keccak: data.remove(&BuiltinName::keccak).unwrap_or_default(),
            mul_mod: data.remove(&BuiltinName::mul_mod).unwrap_or_default(),
            pedersen: data.remove(&BuiltinName::pedersen).unwrap_or_default(),
            poseidon: data.remove(&BuiltinName::poseidon).unwrap_or_default(),
            range_check: data.remove(&BuiltinName::range_check).unwrap_or_default(),
            range_check96: data.remove(&BuiltinName::range_check96).unwrap_or_default(),
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

    /// Updates the bouncer with a new transaction.
    pub fn try_update<S: StateReader>(
        &mut self,
        state_reader: &S,
        tx_state_changes_keys: &StateChangesKeys,
        tx_execution_summary: &ExecutionSummary,
        tx_resources: &TransactionResources,
    ) -> TransactionExecutorResult<()> {
        // The countings here should be linear in the transactional state changes and execution info
        // rather than the cumulative state attributes.
        let marginal_state_changes_keys =
            tx_state_changes_keys.difference(&self.state_changes_keys);
        let marginal_executed_class_hashes = tx_execution_summary
            .executed_class_hashes
            .difference(&self.executed_class_hashes)
            .cloned()
            .collect();
        let n_marginal_visited_storage_entries = tx_execution_summary
            .visited_storage_entries
            .difference(&self.visited_storage_entries)
            .count();
        let tx_weights = get_tx_weights(
            state_reader,
            &marginal_executed_class_hashes,
            n_marginal_visited_storage_entries,
            tx_resources,
            &marginal_state_changes_keys,
        )?;

        // Check if the transaction can fit the current block available capacity.
        if !self.bouncer_config.has_room(self.accumulated_weights + tx_weights) {
            log::debug!(
                "Transaction cannot be added to the current block, block capacity reached; \
                 transaction weights: {tx_weights:?}, block weights: {:?}.",
                self.accumulated_weights
            );
            Err(TransactionExecutorError::BlockFull)?
        }

        self.update(tx_weights, tx_execution_summary, &marginal_state_changes_keys);

        Ok(())
    }

    fn update(
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

    #[cfg(test)]
    pub fn set_accumulated_weights(&mut self, weights: BouncerWeights) {
        self.accumulated_weights = weights;
    }
}

pub fn get_tx_weights<S: StateReader>(
    state_reader: &S,
    executed_class_hashes: &HashSet<ClassHash>,
    n_visited_storage_entries: usize,
    tx_resources: &TransactionResources,
    state_changes_keys: &StateChangesKeys,
) -> TransactionExecutionResult<BouncerWeights> {
    let (message_segment_length, gas_usage) =
        tx_resources.starknet_resources.calculate_message_l1_resources();

    let mut additional_os_resources =
        get_casm_hash_calculation_resources(state_reader, executed_class_hashes)?;
    additional_os_resources += &get_particia_update_resources(n_visited_storage_entries);

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

/// Returns the estimated Cairo resources for Casm hash calculation (done by the OS), of the given
/// classes.
pub fn get_casm_hash_calculation_resources<S: StateReader>(
    state_reader: &S,
    executed_class_hashes: &HashSet<ClassHash>,
) -> TransactionExecutionResult<ExecutionResources> {
    let mut casm_hash_computation_resources = ExecutionResources::default();

    for class_hash in executed_class_hashes {
        let class = state_reader.get_compiled_contract_class(*class_hash)?;
        casm_hash_computation_resources += &class.estimate_casm_hash_computation_resources();
    }

    Ok(casm_hash_computation_resources)
}

/// Returns the estimated Cairo resources for Patricia tree updates, or hash invocations
/// (done by the OS), required for accessing (read/write) the given storage entries.
// For each tree: n_visited_leaves * log(n_initialized_leaves)
// as the height of a Patricia tree with N uniformly distributed leaves is ~log(N),
// and number of visited leaves includes reads and writes.
pub fn get_particia_update_resources(n_visited_storage_entries: usize) -> ExecutionResources {
    const TREE_HEIGHT_UPPER_BOUND: usize = 24;
    let n_updates = n_visited_storage_entries * TREE_HEIGHT_UPPER_BOUND;

    ExecutionResources {
        // TODO(Yoni, 1/5/2024): re-estimate this.
        n_steps: 32 * n_updates,
        // For each Patricia update there are two hash calculations.
        builtin_instance_counter: HashMap::from([(BuiltinName::pedersen, 2 * n_updates)]),
        n_memory_holes: 0,
    }
}

pub fn verify_tx_weights_in_bounds<S: StateReader>(
    state_reader: &S,
    tx_execution_summary: &ExecutionSummary,
    tx_resources: &TransactionResources,
    tx_state_changes_keys: &StateChangesKeys,
    bouncer_config: &BouncerConfig,
) -> TransactionExecutionResult<()> {
    let tx_weights = get_tx_weights(
        state_reader,
        &tx_execution_summary.executed_class_hashes,
        tx_execution_summary.visited_storage_entries.len(),
        tx_resources,
        tx_state_changes_keys,
    )?;

    if !bouncer_config.has_room(tx_weights) {
        return Err(TransactionExecutionError::TransactionTooLarge);
    }

    Ok(())
}
