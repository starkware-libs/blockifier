use std::collections::HashSet;
use std::vec::IntoIter;

use cairo_vm::serde::deserialize_program::BuiltinName;
use derive_more::Add;
use serde::Deserialize;
use starknet_api::core::ClassHash;

use crate::abi::constants;
use crate::blockifier::transaction_executor::{
    get_casm_hash_calculation_resources, get_particia_update_resources, TransactionExecutorResult,
};
use crate::execution::call_info::{CallInfo, MessageL1CostInfo};
use crate::fee::gas_usage::get_onchain_data_segment_length;
use crate::state::cached_state::{StateChangesKeys, StorageEntry, TransactionalState};
use crate::state::state_api::StateReader;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionInfo};

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

#[derive(Clone, Copy, Debug, Default, derive_more::Sub, Deserialize, PartialEq)]
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

#[derive(Add, Clone, Copy, Debug, Default, derive_more::Sub, Deserialize, PartialEq)]
pub struct BuiltinCount {
    bitwise: usize,
    ecdsa: usize,
    ec_op: usize,
    keccak: usize,
    output: usize,
    pedersen: usize,
    poseidon: usize,
    range_check: usize,
}

impl BuiltinCount {
    impl_checked_sub!(bitwise, ecdsa, ec_op, keccak, output, pedersen, poseidon, range_check);
}

impl From<&ResourcesMapping> for BuiltinCount {
    fn from(resources: &ResourcesMapping) -> Self {
        Self {
            bitwise: resources.get_or_default(BuiltinName::bitwise.name()),
            ecdsa: resources.get_or_default(BuiltinName::ecdsa.name()),
            ec_op: resources.get_or_default(BuiltinName::ec_op.name()),
            keccak: resources.get_or_default(BuiltinName::keccak.name()),
            output: resources.get_or_default(BuiltinName::output.name()),
            pedersen: resources.get_or_default(BuiltinName::pedersen.name()),
            poseidon: resources.get_or_default(BuiltinName::poseidon.name()),
            range_check: resources.get_or_default(BuiltinName::range_check.name()),
        }
    }
}

#[derive(Clone)]
pub struct Bouncer {
    pub executed_class_hashes: HashSet<ClassHash>,
    pub visited_storage_entries: HashSet<StorageEntry>,
    pub state_changes_keys: StateChangesKeys,
    // The capacity is calculated based of the values of the other Bouncer fields.
    available_capacity: BouncerWeights,
    // The maximum capacity of the block is contant throughout a block lifecycle.
    max_capacity: BouncerWeights,
}

impl Bouncer {
    pub fn new(capacity: BouncerWeights) -> Self {
        Bouncer {
            executed_class_hashes: HashSet::new(),
            state_changes_keys: StateChangesKeys::default(),
            visited_storage_entries: HashSet::new(),
            available_capacity: capacity,
            max_capacity: capacity,
        }
    }

    pub fn create_transactional(self) -> TransactionalBouncer {
        TransactionalBouncer::new(self)
    }

    pub fn merge(&mut self, other: Bouncer) {
        self.executed_class_hashes.extend(other.executed_class_hashes);
        self.state_changes_keys.extend(&other.state_changes_keys);
        self.visited_storage_entries.extend(other.visited_storage_entries);
        self.available_capacity = other.available_capacity;
    }
}

#[derive(Clone)]
pub struct TransactionalBouncer {
    // The parent bouncer can be modified only through the merge method.
    parent: Bouncer,
    // The transactional bouncer can be modified only through the update method.
    child: Bouncer,
}

impl TransactionalBouncer {
    pub fn new(parent: Bouncer) -> TransactionalBouncer {
        let capacity = parent.available_capacity;
        TransactionalBouncer { parent, child: Bouncer::new(capacity) }
    }

    pub fn update<S: StateReader>(
        &mut self,
        state: &mut TransactionalState<'_, S>,
        tx_execution_info: &TransactionExecutionInfo,
        l1_handler_payload_size: Option<usize>,
    ) -> TransactionExecutorResult<()> {
        self.update_used_state_entries_sets(tx_execution_info, state)?;
        self.update_capacity(state, tx_execution_info, l1_handler_payload_size)?;

        // TODO what about timestamps (we need to close the block in case that there is a
        // transaction that is older than the max_lifespan), should this logic be in the bouncer or
        // outside?

        Ok(())
    }

    fn update_capacity<S: StateReader>(
        &mut self,
        state: &mut TransactionalState<'_, S>,
        tx_execution_info: &TransactionExecutionInfo,
        l1_handler_payload_size: Option<usize>,
    ) -> TransactionExecutorResult<()> {
        let (tx_n_steps, tx_builtin_count) =
            self.calc_n_steps_and_builtin_count(&tx_execution_info.actual_resources, state)?;
        // Note: this counting does not take into account state changes that happen in the block
        // level. E.g., the felt that encodes the number of modified contracts in a block.
        let tx_state_diff_size =
            get_onchain_data_segment_length(self.child.state_changes_keys.count());
        let message_segment_length =
            calc_message_segment_length(tx_execution_info, l1_handler_payload_size)?;

        let tx_weights = BouncerWeights {
            gas: tx_execution_info.actual_resources.get_or_default(constants::L1_GAS_USAGE),
            n_steps: tx_n_steps,
            message_segment_length,
            state_diff_size: tx_state_diff_size,
            n_events: tx_execution_info.get_number_of_events(),
            builtin_count: tx_builtin_count,
        };

        // Check if the transaction is too large to fit any block.
        self.parent
            .max_capacity
            .checked_sub(tx_weights)
            .ok_or(TransactionExecutionError::TxTooLarge)?;

        // Check if the transaction can fit the current block available capacity.
        self.child.available_capacity = self
            .child
            .available_capacity
            .checked_sub(tx_weights)
            .ok_or(TransactionExecutionError::BlockFull)?;
        Ok(())
    }

    // TODO update function (in the following PRs)

    pub fn calc_n_steps_and_builtin_count<S: StateReader>(
        &self,
        execution_info_resources: &ResourcesMapping,
        state: &mut TransactionalState<'_, S>,
    ) -> TransactionExecutorResult<(usize, BuiltinCount)> {
        // Count the additional OS resources that are not present in the transaction exection info.
        let mut additional_os_resources = get_casm_hash_calculation_resources(
            state,
            &self.parent.executed_class_hashes,
            &self.child.executed_class_hashes,
        )?;
        additional_os_resources += &get_particia_update_resources(
            &self.parent.visited_storage_entries,
            &self.child.visited_storage_entries,
        )?;
        let additional_builtin_count =
            BuiltinCount::from(&ResourcesMapping(additional_os_resources.builtin_instance_counter));

        // Sum all the builtin resources.
        let execution_info_builtin_count = BuiltinCount::from(execution_info_resources);
        let builtin_count = execution_info_builtin_count + additional_builtin_count;

        // The n_steps counter also includes the count of memory holes.
        let n_steps = additional_os_resources.n_steps
            + execution_info_resources.get_or_default(constants::N_STEPS_RESOURCE)
            + additional_os_resources.n_memory_holes
            + execution_info_resources.get_or_default(constants::N_MEMORY_HOLES);

        Ok((n_steps, builtin_count))
    }

    pub fn update_used_state_entries_sets<S: StateReader>(
        &mut self,
        tx_execution_info: &TransactionExecutionInfo,
        state: &mut TransactionalState<'_, S>,
    ) -> TransactionExecutorResult<()> {
        self.child.executed_class_hashes.extend(tx_execution_info.get_executed_class_hashes());
        self.child.visited_storage_entries.extend(tx_execution_info.get_visited_storage_entries());
        let tx_state_changes_keys = state.get_actual_state_changes()?.into_keys();
        self.child.state_changes_keys =
            tx_state_changes_keys.difference(&self.parent.state_changes_keys);
        Ok(())
    }

    pub fn commit(mut self) -> Bouncer {
        self.parent.merge(self.child);
        self.parent
    }

    pub fn abort(self) -> Bouncer {
        self.parent
    }
}

pub fn calc_message_segment_length(
    tx_execution_info: &TransactionExecutionInfo,
    l1_handler_payload_size: Option<usize>,
) -> TransactionExecutorResult<usize> {
    let call_infos: IntoIter<&CallInfo> =
        [&tx_execution_info.validate_call_info, &tx_execution_info.execute_call_info]
            .iter()
            .filter_map(|&call_info| call_info.as_ref())
            .collect::<Vec<&CallInfo>>()
            .into_iter();
    let msg_l1_cost_info = MessageL1CostInfo::calculate(call_infos, l1_handler_payload_size)?;
    Ok(msg_l1_cost_info.message_segment_length)
}
