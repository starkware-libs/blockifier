use std::collections::{HashMap, HashSet};
use std::vec::IntoIter;

use cairo_vm::serde::deserialize_program::BuiltinName;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use serde::Deserialize;
use starknet_api::core::ClassHash;

use crate::abi::constants;
use crate::blockifier::transaction_executor::{
    get_casm_hash_calculation_resources, get_particia_update_resources, TransactionExecutorResult,
};
use crate::execution::call_info::{CallInfo, MessageL1CostInfo};
use crate::fee::gas_usage::{get_messages_gas_usage, get_onchain_data_segment_length};
use crate::state::cached_state::{StateChangesKeys, StorageEntry, TransactionalState};
use crate::state::state_api::StateReader;
use crate::transaction::objects::TransactionExecutionInfo;
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

impl From<HashMapWrapper> for BouncerWeights {
    fn from(mut data: HashMapWrapper) -> Self {
        Self {
            gas: data.remove(constants::L1_GAS_USAGE).unwrap_or_default(),
            n_steps: data.remove(constants::N_STEPS_RESOURCE).unwrap_or_default()
                + data.remove(constants::N_MEMORY_HOLES).unwrap_or_default(),
            message_segment_length: data
                .remove(constants::MESSAGE_SEGMENT_LENGTH)
                .unwrap_or_default(),
            state_diff_size: data.remove(constants::STATE_DIFF_SIZE).unwrap_or_default(),
            n_events: data.remove(constants::N_EVENTS).unwrap_or_default(),
            builtin_count: BuiltinCount::from(data),
        }
    }
}

impl From<ExecutionResources> for BouncerWeights {
    fn from(val: ExecutionResources) -> Self {
        let mut weights = BouncerWeights::from(val.builtin_instance_counter);
        weights.n_steps = val.n_steps + val.n_memory_holes;
        weights
    }
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

impl From<HashMapWrapper> for BuiltinCount {
    fn from(mut data: HashMapWrapper) -> Self {
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

impl BuiltinCount {
    impl_checked_sub!(bitwise, ecdsa, ec_op, keccak, pedersen, poseidon, range_check);
}

#[derive(Clone)]
pub struct Bouncer {
    pub executed_class_hashes: HashSet<ClassHash>,
    pub visited_storage_entries: HashSet<StorageEntry>,
    pub state_changes_keys: StateChangesKeys,
    // The capacity is calculated based of the values of the other Bouncer fields.
    capacity: BouncerWeights,
}

impl Bouncer {
    pub fn new(capacity: BouncerWeights) -> Self {
        Bouncer {
            executed_class_hashes: HashSet::new(),
            state_changes_keys: StateChangesKeys::default(),
            visited_storage_entries: HashSet::new(),
            capacity,
        }
    }

    pub fn create_transactional(self) -> TransactionalBouncer {
        TransactionalBouncer::new(self)
    }

    pub fn merge(&mut self, other: Bouncer) {
        self.executed_class_hashes.extend(other.executed_class_hashes);
        self.state_changes_keys.extend(&other.state_changes_keys);
        self.visited_storage_entries.extend(other.visited_storage_entries);
        self.capacity = other.capacity;
    }
}

#[derive(Clone)]
pub struct TransactionalBouncer {
    // The bouncer can be modified only through the merge method.
    bouncer: Bouncer,
    // The transactional bouncer can be modified only through the update method.
    transactional: Bouncer,
}

impl TransactionalBouncer {
    pub fn new(parent: Bouncer) -> TransactionalBouncer {
        let capacity = parent.capacity;
        TransactionalBouncer { bouncer: parent, transactional: Bouncer::new(capacity) }
    }

    // TODO update function (in the next PRs)

    pub fn get_tx_weights<S: StateReader>(
        &mut self,
        state: &mut TransactionalState<'_, S>,
        tx_execution_info: &TransactionExecutionInfo,
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
        let tx_execution_info_weights = Self::get_tx_execution_info_resources_weights(
            tx_execution_info,
            l1_handler_payload_size,
        )?;

        let mut tx_weights =
            BouncerWeights::from(additional_os_resources) + tx_execution_info_weights;
        tx_weights.state_diff_size =
            get_onchain_data_segment_length(&self.transactional.state_changes_keys.count());
        Ok(tx_weights)
    }

    pub fn get_tx_execution_info_resources_weights(
        tx_execution_info: &TransactionExecutionInfo,
        l1_handler_payload_size: Option<usize>,
    ) -> TransactionExecutorResult<BouncerWeights> {
        let mut execution_info_resources = tx_execution_info.bouncer_resources.0.clone();

        // The blob gas is not being limited by the bouncer, thus we don't use it here.
        // The gas is determined by the state diff size, which is limited by the bouncer.
        execution_info_resources.remove(constants::BLOB_GAS_USAGE);

        // TODO(Avi, 30/03/2024): Consider removing "l1_gas_usage" from actual resources.
        // This value is not used, instead we use the value from calc_message_l1_resources() below.
        execution_info_resources.remove(constants::L1_GAS_USAGE);

        let mut weights = BouncerWeights::from(execution_info_resources);
        (weights.message_segment_length, weights.gas) =
            calculate_message_l1_resources(tx_execution_info, l1_handler_payload_size)?;
        // TODO: consider getting n_events from tx_execution_info.summarize() in the following PRs
        weights.n_events = tx_execution_info.get_number_of_events();
        Ok(weights)
    }

    pub fn update_auxiliary_info<S: StateReader>(
        &mut self,
        tx_execution_info: &TransactionExecutionInfo,
        state: &mut TransactionalState<'_, S>,
    ) -> TransactionExecutorResult<()> {
        let tx_execution_summary = tx_execution_info.summarize();
        self.transactional.executed_class_hashes.extend(tx_execution_summary.executed_class_hashes);
        self.transactional
            .visited_storage_entries
            .extend(tx_execution_summary.visited_storage_entries);
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

/// Calculates the l1 resources used by l1 and l2 messages.
/// Returns the total message segment length and the l1 gas usage.
pub fn calculate_message_l1_resources(
    tx_execution_info: &TransactionExecutionInfo,
    l1_handler_payload_size: Option<usize>,
) -> TransactionExecutorResult<(usize, usize)> {
    let call_infos: IntoIter<&CallInfo> =
        [&tx_execution_info.validate_call_info, &tx_execution_info.execute_call_info]
            .iter()
            .filter_map(|&call_info| call_info.as_ref())
            .collect::<Vec<&CallInfo>>()
            .into_iter();

    let message_cost_info = MessageL1CostInfo::calculate(call_infos, l1_handler_payload_size)?;
    let message_gas_usage = get_messages_gas_usage(&message_cost_info, l1_handler_payload_size);
    // TODO(Avi, 30/03/2024): Consider removing "l1_gas_usage" from actual resources.
    let gas_weight = usize_from_u128(message_gas_usage.l1_gas)
        .expect("This conversion should not fail as the value is a converted usize.");

    Ok((message_cost_info.message_segment_length, gas_weight))
}
