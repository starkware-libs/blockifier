use std::collections::{HashMap, HashSet};

use cairo_vm::serde::deserialize_program::BuiltinName;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use serde::Deserialize;
use starknet_api::core::ClassHash;

use crate::abi::constants;
use crate::blockifier::transaction_executor::{
    get_casm_hash_calculation_resources, get_particia_update_resources, TransactionExecutorResult,
};
use crate::execution::call_info::{ExecutionSummary, MessageL1CostInfo};
use crate::fee::gas_usage::{
    get_message_segment_length, get_messages_gas_usage, get_onchain_data_segment_length,
};
use crate::state::cached_state::{StateChangesKeys, StorageEntry, TransactionalState};
use crate::state::state_api::StateReader;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionInfo};
use crate::utils::usize_from_u128;

#[cfg(test)]
#[path = "bouncer_test.rs"]
mod test;

pub type HashMapWrapper = HashMap<String, usize>;

#[derive(Clone, Default)]
pub struct BouncerConfig {
    pub block_max_capacity: BouncerWeights,
    pub block_max_capacity_with_keccak: BouncerWeights,
}

#[derive(Clone, Copy, Debug, Default, derive_more::Add, Deserialize, PartialEq)]
/// Represents the execution resources counted throughout block creation.
pub struct BouncerWeights {
    builtin_count: BuiltinCount,
    gas: usize,
    message_segment_length: usize,
    n_events: usize,
    n_steps: usize,
    state_diff_size: usize,
}

impl BouncerWeights {
    pub fn exceeds(&self, other: &Self) -> bool {
        if self.gas > other.gas
            || self.message_segment_length > other.message_segment_length
            || self.n_events > other.n_events
            || self.n_steps > other.n_steps
            || self.state_diff_size > other.state_diff_size
            || self.builtin_count.exceeds(other.builtin_count)
        {
            return true;
        }
        false
    }
}

impl From<ExecutionResources> for BouncerWeights {
    fn from(data: ExecutionResources) -> Self {
        BouncerWeights {
            n_steps: data.n_steps + data.n_memory_holes,
            builtin_count: data.builtin_instance_counter.into(),
            ..Default::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Default, derive_more::Add, Deserialize, PartialEq)]
pub struct BuiltinCount {
    bitwise: usize,
    ecdsa: usize,
    ec_op: usize,
    keccak: usize,
    pedersen: usize,
    poseidon: usize,
    range_check: usize,
}

impl BuiltinCount {
    pub fn exceeds(&self, other: Self) -> bool {
        if self.bitwise > other.bitwise
            || self.ecdsa > other.ecdsa
            || self.ec_op > other.ec_op
            || self.keccak > other.keccak
            || self.pedersen > other.pedersen
            || self.poseidon > other.poseidon
            || self.range_check > other.range_check
        {
            return true;
        }
        false
    }
}

impl From<HashMapWrapper> for BuiltinCount {
    fn from(mut data: HashMapWrapper) -> Self {
        // TODO(yael): replace the unwrap_or_default with expect once the ExecutionResources
        // contains all the builtins.
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

#[derive(Clone, Default)]
pub struct Bouncer {
    pub executed_class_hashes: HashSet<ClassHash>,
    pub visited_storage_entries: HashSet<StorageEntry>,
    pub state_changes_keys: StateChangesKeys,
    pub bouncer_config: BouncerConfig,
    // The capacity is calculated based of the values of the other Bouncer fields.
    accumulated_capacity: BouncerWeights,
}

impl Bouncer {
    pub fn new(bouncer_config: BouncerConfig) -> Self {
        Bouncer { bouncer_config, ..Default::default() }
    }

    fn merge(
        &mut self,
        tx_weights: BouncerWeights,
        tx_execution_summary: &ExecutionSummary,
        state_changes_keys: &StateChangesKeys,
    ) {
        self.accumulated_capacity = self.accumulated_capacity + tx_weights;
        self.visited_storage_entries.extend(&tx_execution_summary.visited_storage_entries);
        self.executed_class_hashes.extend(&tx_execution_summary.executed_class_hashes);
        self.state_changes_keys.extend(state_changes_keys);
    }

    /// Updates the bouncer with a new transaction.
    pub fn update<S: StateReader>(
        &mut self,
        state: &mut TransactionalState<'_, S>,
        tx_execution_info: &TransactionExecutionInfo,
        l1_handler_payload_size: Option<usize>,
    ) -> TransactionExecutorResult<()> {
        let tx_execution_summary = tx_execution_info.summarize();
        self.update_inner(
            state,
            &tx_execution_summary,
            &tx_execution_info.bouncer_resources,
            l1_handler_payload_size,
        )
    }

    fn update_inner<S: StateReader>(
        &mut self,
        state: &mut TransactionalState<'_, S>,
        tx_execution_summary: &ExecutionSummary,
        bouncer_resources: &ResourcesMapping,
        l1_handler_payload_size: Option<usize>,
    ) -> TransactionExecutorResult<()> {
        let state_changes_keys = self.get_state_changes_keys(state)?;
        let tx_weights = self.get_tx_weights(
            state,
            tx_execution_summary,
            bouncer_resources,
            l1_handler_payload_size,
            &state_changes_keys,
        )?;

        let mut max_capacity = self.bouncer_config.block_max_capacity;
        if self.accumulated_capacity.builtin_count.keccak > 0 || tx_weights.builtin_count.keccak > 0
        {
            max_capacity = self.bouncer_config.block_max_capacity_with_keccak;
        }

        // Check if the transaction is too large to fit any block.
        if tx_weights.exceeds(&max_capacity) {
            Err(TransactionExecutionError::TransactionTooLarge)?
        }

        // Check if the transaction can fit the current block available capacity.
        if (self.accumulated_capacity + tx_weights).exceeds(&max_capacity) {
            Err(TransactionExecutionError::BlockFull)?
        }

        self.merge(tx_weights, tx_execution_summary, &state_changes_keys);

        Ok(())
    }

    pub fn get_tx_weights<S: StateReader>(
        &mut self,
        state: &mut TransactionalState<'_, S>,
        tx_execution_summary: &ExecutionSummary,
        bouncer_resources: &ResourcesMapping,
        l1_handler_payload_size: Option<usize>,
        state_changes_keys: &StateChangesKeys,
    ) -> TransactionExecutorResult<BouncerWeights> {
        let mut additional_os_resources = get_casm_hash_calculation_resources(
            state,
            &self.executed_class_hashes,
            &tx_execution_summary.executed_class_hashes,
        )?;
        additional_os_resources += &get_particia_update_resources(
            &self.visited_storage_entries,
            &tx_execution_summary.visited_storage_entries,
        )?;

        let execution_info_weights = Self::get_tx_execution_info_resources_weights(
            tx_execution_summary,
            bouncer_resources,
            l1_handler_payload_size,
        )?;

        let mut tx_weights = BouncerWeights::from(additional_os_resources) + execution_info_weights;

        tx_weights.state_diff_size = get_onchain_data_segment_length(&state_changes_keys.count());
        Ok(tx_weights)
    }

    pub fn get_state_changes_keys<S: StateReader>(
        &self,
        state: &mut TransactionalState<'_, S>,
    ) -> TransactionExecutorResult<StateChangesKeys> {
        let tx_state_changes_keys = state.get_actual_state_changes()?.into_keys();
        Ok(tx_state_changes_keys.difference(&self.state_changes_keys))
    }

    pub fn get_tx_execution_info_resources_weights(
        tx_execution_summary: &ExecutionSummary,
        bouncer_resources: &ResourcesMapping,
        l1_handler_payload_size: Option<usize>,
    ) -> TransactionExecutorResult<BouncerWeights> {
        let mut execution_info_resources = bouncer_resources.0.clone();

        let (message_segment_length, gas_usage) = calculate_message_l1_resources(
            &tx_execution_summary.l2_to_l1_payload_lengths,
            l1_handler_payload_size,
        );

        // The blob gas is not being limited by the bouncer, thus we don't use it here.
        // The gas is determined by the state diff size, which is limited by the bouncer.
        execution_info_resources.remove(constants::BLOB_GAS_USAGE);

        // TODO(Avi, 30/03/2024): Consider removing "l1_gas_usage" from actual resources.
        // This value is not used, instead we use the value from calc_message_l1_resources() below.
        execution_info_resources.remove(constants::L1_GAS_USAGE);

        let weights = BouncerWeights {
            gas: gas_usage,
            message_segment_length,
            n_events: tx_execution_summary.n_events,
            n_steps: execution_info_resources
                .remove(constants::N_STEPS_RESOURCE)
                .expect("n_steps must be present in the execution info")
                + execution_info_resources
                    .remove(constants::N_MEMORY_HOLES)
                    .expect("n_memory_holes must be present in the execution info"),
            builtin_count: BuiltinCount::from(execution_info_resources),
            state_diff_size: 0,
        };

        Ok(weights)
    }
}

/// Calculates the L1 resources used by L1<>L2 messages.
/// Returns the total message segment length and the gas weight.
pub fn calculate_message_l1_resources(
    l2_to_l1_payload_lengths: &[usize],
    l1_handler_payload_size: Option<usize>,
) -> (usize, usize) {
    let message_segment_length =
        get_message_segment_length(l2_to_l1_payload_lengths, l1_handler_payload_size);
    let gas_usage = get_messages_gas_usage(
        &MessageL1CostInfo {
            l2_to_l1_payload_lengths: l2_to_l1_payload_lengths.to_owned(),
            message_segment_length,
        },
        l1_handler_payload_size,
    );
    // TODO(Avi, 30/03/2024): Consider removing "l1_gas_usage" from actual resources.
    let gas_weight = usize_from_u128(gas_usage.l1_gas)
        .expect("This conversion should not fail as the value is a converted usize.");
    (message_segment_length, gas_weight)
}
