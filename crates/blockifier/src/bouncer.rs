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

pub struct BouncerConfig {
    pub block_max_capacity: BouncerWeights,
    pub block_max_capacity_with_keccak: BouncerWeights,
}

#[derive(
    Clone, Copy, Debug, Default, derive_more::Add, derive_more::Sub, Deserialize, PartialEq,
)]
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
    impl_checked_sub!(
        builtin_count,
        gas,
        message_segment_length,
        n_events,
        n_steps,
        state_diff_size
    );
}

impl From<ExecutionResources> for BouncerWeights {
    fn from(data: ExecutionResources) -> Self {
        BouncerWeights {
            n_steps: data.n_steps + data.n_memory_holes,
            builtin_count: BuiltinCount {
                pedersen: *data
                    .builtin_instance_counter
                    .get(BuiltinName::pedersen.name())
                    .unwrap_or(&0),
                poseidon: *data
                    .builtin_instance_counter
                    .get(BuiltinName::poseidon.name())
                    .unwrap_or(&0),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

#[derive(
    Clone, Copy, Debug, Default, derive_more::Add, derive_more::Sub, Deserialize, PartialEq,
)]
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
    impl_checked_sub!(bitwise, ecdsa, ec_op, keccak, pedersen, poseidon, range_check);
}

impl From<HashMapWrapper> for BuiltinCount {
    fn from(mut data: HashMapWrapper) -> Self {
        let builtin_count = Self {
            bitwise: data.remove(BuiltinName::bitwise.name()).expect("bitwise must be present"),
            ecdsa: data.remove(BuiltinName::ecdsa.name()).expect("ecdsa must be present"),
            ec_op: data.remove(BuiltinName::ec_op.name()).expect("ec_op must be present"),
            keccak: data.remove(BuiltinName::keccak.name()).expect("keccak must be present"),
            pedersen: data.remove(BuiltinName::pedersen.name()).expect("pedersen must be present"),
            poseidon: data.remove(BuiltinName::poseidon.name()).expect("poseidon must be present"),
            range_check: data
                .remove(BuiltinName::range_check.name())
                .expect("range_check must be present"),
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
    pub block_contains_keccak: bool,
    // The capacity is calculated based of the values of the other Bouncer fields.
    available_capacity: BouncerWeights,
}

impl Bouncer {
    pub fn new(available_capacity: BouncerWeights, block_contains_keccak: bool) -> Self {
        Bouncer {
            executed_class_hashes: HashSet::new(),
            state_changes_keys: StateChangesKeys::default(),
            visited_storage_entries: HashSet::new(),
            available_capacity,
            block_contains_keccak,
        }
    }

    pub fn create_transactional(self) -> TransactionalBouncer {
        TransactionalBouncer::new(self)
    }

    pub fn merge(&mut self, other: Bouncer) {
        self.executed_class_hashes.extend(other.executed_class_hashes);
        self.state_changes_keys.extend(&other.state_changes_keys);
        self.visited_storage_entries.extend(other.visited_storage_entries);
        self.block_contains_keccak = other.block_contains_keccak;
        self.available_capacity = other.available_capacity;
    }
}

#[derive(Clone)]
pub struct TransactionalBouncer {
    // The block bouncer can be modified only through the merge method.
    bouncer: Bouncer,
    // The transaction bouncer can be modified only through the update method.
    transactional: Bouncer,
}

impl TransactionalBouncer {
    pub fn new(block_bouncer: Bouncer) -> TransactionalBouncer {
        let transactional =
            Bouncer::new(block_bouncer.available_capacity, block_bouncer.block_contains_keccak);
        TransactionalBouncer { bouncer: block_bouncer, transactional }
    }

    /// Updates the bouncer with a new transaction info and weights after execution.
    pub fn update<S: StateReader>(
        &mut self,
        bouncer_config: &BouncerConfig,
        state: &mut TransactionalState<'_, S>,
        tx_execution_info: &TransactionExecutionInfo,
        l1_handler_payload_size: Option<usize>,
    ) -> TransactionExecutorResult<()> {
        let tx_execution_summary = tx_execution_info.summarize();
        self.update_auxiliary_info(state, &tx_execution_summary)?;
        self.update_available_capacity(
            bouncer_config,
            state,
            &tx_execution_summary,
            &tx_execution_info.bouncer_resources,
            l1_handler_payload_size,
        )?;

        Ok(())
    }

    /// This function is called by the update function to update the bouncer capacity.
    fn update_available_capacity<S: StateReader>(
        &mut self,
        bouncer_config: &BouncerConfig,
        state: &mut TransactionalState<'_, S>,
        tx_execution_summary: &ExecutionSummary,
        bouncer_resources: &ResourcesMapping,
        l1_handler_payload_size: Option<usize>,
    ) -> TransactionExecutorResult<()> {
        let tx_weights = self.get_tx_weights(
            state,
            tx_execution_summary,
            bouncer_resources,
            l1_handler_payload_size,
        )?;

        self.update_available_capacity_with_keccak_if_needed(
            tx_weights.builtin_count.keccak,
            bouncer_config,
        )?;

        // Check if the transaction is too large to fit any block.
        let mut max_capacity = bouncer_config.block_max_capacity;
        if self.transactional.block_contains_keccak {
            max_capacity = bouncer_config.block_max_capacity_with_keccak;
        }
        max_capacity.checked_sub(tx_weights).ok_or(TransactionExecutionError::TxTooLarge)?;

        // Check if the transaction can fit the current block available capacity.
        self.transactional.available_capacity = self
            .transactional
            .available_capacity
            .checked_sub(tx_weights)
            .ok_or(TransactionExecutionError::BlockFull)?;
        Ok(())
    }

    fn update_available_capacity_with_keccak_if_needed(
        &mut self,
        keccak_builtin_count: usize,
        bouncer_config: &BouncerConfig,
    ) -> TransactionExecutorResult<()> {
        // Check if this is the first transaction in the block that contains keccak.
        if self.transactional.block_contains_keccak || keccak_builtin_count == 0 {
            return Ok(());
        }
        // First zero the keccak capacity to be able to subtract the max_capacity_with_keccak from
        // max_capacity (that is without keccak).
        let mut max_capacity_with_keccak_tmp = bouncer_config.block_max_capacity_with_keccak;
        max_capacity_with_keccak_tmp.builtin_count.keccak = 0;
        // compute the diff between the max_capacity and the max_capacity_with_keccak.
        let max_capacity_with_keccak_diff = bouncer_config
            .block_max_capacity
            .checked_sub(max_capacity_with_keccak_tmp)
            .expect("max_capacity_with_keccak should be smaller than max_capacity");
        // Subtract the diff from the available capacity.
        self.transactional.available_capacity = self
            .transactional
            .available_capacity
            .checked_sub(max_capacity_with_keccak_diff)
            .ok_or(TransactionExecutionError::BlockFull)?;
        // Add back the keccack capacity that was reset at the beggining.
        self.transactional.available_capacity.builtin_count.keccak =
            bouncer_config.block_max_capacity_with_keccak.builtin_count.keccak;
        // Mark this block as contains keccak.
        self.transactional.block_contains_keccak = true;
        Ok(())
    }

    pub fn get_tx_weights<S: StateReader>(
        &mut self,
        state: &mut TransactionalState<'_, S>,
        tx_execution_summary: &ExecutionSummary,
        bouncer_resources: &ResourcesMapping,
        l1_handler_payload_size: Option<usize>,
    ) -> TransactionExecutorResult<BouncerWeights> {
        let mut additional_os_resources = get_casm_hash_calculation_resources(
            state,
            &self.bouncer.executed_class_hashes,
            &self.transactional.executed_class_hashes,
        )?;
        additional_os_resources += &get_particia_update_resources(
            &self.bouncer.visited_storage_entries,
            &self.transactional.visited_storage_entries,
        )?;

        let execution_info_weights = Self::get_tx_execution_info_resources_weights(
            tx_execution_summary,
            bouncer_resources,
            l1_handler_payload_size,
        )?;

        let mut tx_weights = BouncerWeights::from(additional_os_resources) + execution_info_weights;
        tx_weights.state_diff_size =
            get_onchain_data_segment_length(&self.transactional.state_changes_keys.count());
        Ok(tx_weights)
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

    pub fn update_auxiliary_info<S: StateReader>(
        &mut self,
        state: &mut TransactionalState<'_, S>,
        tx_execution_summary: &ExecutionSummary,
    ) -> TransactionExecutorResult<()> {
        // TODO(Yael): consider removing the auxiliary_info from the bouncer and using the
        // ExecutionSummary directly.
        self.transactional
            .executed_class_hashes
            .extend(&tx_execution_summary.executed_class_hashes);
        self.transactional
            .visited_storage_entries
            .extend(&tx_execution_summary.visited_storage_entries);
        let tx_state_changes_keys = state.get_actual_state_changes()?.into_keys();
        self.transactional.state_changes_keys =
            tx_state_changes_keys.difference(&self.bouncer.state_changes_keys);
        Ok(())
    }

    pub fn commit(mut self) -> Bouncer {
        self.bouncer.merge(self.transactional);
        self.bouncer
    }

    pub fn abort(self) -> Bouncer {
        self.bouncer
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
