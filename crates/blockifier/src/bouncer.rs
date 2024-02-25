use std::collections::HashSet;
use std::vec::IntoIter;

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
use crate::transaction::transaction_execution::Transaction;

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
    gas: usize,
    n_steps: usize,
    message_segment_length: usize,
    state_diff_size: usize,
    n_events: usize,
    builtin_count: BuiltinCount,
}

impl BouncerWeights {
    impl_checked_sub!(
        gas,
        n_steps,
        message_segment_length,
        state_diff_size,
        n_events,
        builtin_count
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
    segment_arena: usize, // needed here? If was not present in the original bouncer code
}

impl From<&ResourcesMapping> for BuiltinCount {
    fn from(resource_mapping: &ResourcesMapping) -> Self {
        Self {
            bitwise: resource_mapping.get_builtin_count("bitwise"),
            ecdsa: resource_mapping.get_builtin_count("ecdsa"),
            ec_op: resource_mapping.get_builtin_count("ec_op"),
            keccak: resource_mapping.get_builtin_count("keccak"),
            output: resource_mapping.get_builtin_count("output"),
            pedersen: resource_mapping.get_builtin_count("pedersen"),
            poseidon: resource_mapping.get_builtin_count("poseidon"),
            range_check: resource_mapping.get_builtin_count("range_check"),
            segment_arena: resource_mapping.get_builtin_count("segment_arena"),
        }
    }
}

impl BuiltinCount {
    impl_checked_sub!(
        bitwise,
        ecdsa,
        ec_op,
        keccak,
        output,
        pedersen,
        poseidon,
        range_check,
        segment_arena
    );
}

#[derive(Clone)]
pub struct Bouncer {
    pub executed_class_hashes: HashSet<ClassHash>,
    pub visited_storage_entries: HashSet<StorageEntry>,
    pub state_changes_keys: StateChangesKeys,
    pub available_capacity: BouncerWeights,
    // The maximum capacity of the block is contant throughout a block lifecycle.
    max_capacity: BouncerWeights,
}

impl Bouncer {
    fn new(available_capacity: BouncerWeights, max_block_capacity: BouncerWeights) -> Self {
        Bouncer {
            executed_class_hashes: HashSet::new(),
            visited_storage_entries: HashSet::new(),
            state_changes_keys: StateChangesKeys::default(),
            available_capacity,
            max_capacity: max_block_capacity,
        }
    }

    pub fn new_block_bouncer(max_block_capacity: BouncerWeights) -> Bouncer {
        Bouncer::new(max_block_capacity, max_block_capacity)
    }

    pub fn create_transactional(self) -> TransactionBouncer {
        TransactionBouncer::new(self)
    }

    pub fn merge(&mut self, other: Bouncer) {
        self.executed_class_hashes.extend(other.executed_class_hashes);
        self.visited_storage_entries.extend(other.visited_storage_entries);
        self.state_changes_keys.extend(&other.state_changes_keys);
        self.available_capacity = other.available_capacity;
    }
}

#[derive(Clone)]
pub struct TransactionBouncer {
    // The parent bouncer can only be modified by merging the transactional bouncer into it.
    parent: Bouncer,
    // The transactional bouncer is modified according to the transaction execution.
    transactional: Bouncer,
}

impl TransactionBouncer {
    pub fn new(parent: Bouncer) -> TransactionBouncer {
        let transactional = Bouncer::new(parent.available_capacity, parent.max_capacity);
        TransactionBouncer { parent, transactional }
    }

    pub fn update<S: StateReader>(
        &mut self,
        state: &mut TransactionalState<'_, S>,
        tx_execution_info: TransactionExecutionInfo,
        tx: Transaction,
    ) -> TransactionExecutorResult<()> {
        self.update_used_state_entries_sets(&tx_execution_info, state)?;
        self.update_capacity(state, &tx_execution_info, &tx)?;

        // TODO what about timestamps (we need to close the block in case that there is a
        // transaction that is older than the max_lifespan), should this logic be in the bouncer or
        // outside?

        Ok(())
    }

    fn update_capacity<S: StateReader>(
        &mut self,
        state: &mut TransactionalState<'_, S>,
        tx_execution_info: &TransactionExecutionInfo,
        tx: &Transaction,
    ) -> TransactionExecutorResult<()> {
        let (tx_n_steps, tx_builtin_count) =
            self.calc_n_steps_and_builtin_count(&tx_execution_info.actual_resources, state)?;
        // Note: this counting does not take into account state changes that happen in the block level.
        // E.g., the felt that encodes the number of modified contracts in a block.
        let tx_state_diff_size =
            get_onchain_data_segment_length(self.transactional.state_changes_keys.count());

        let tx_weights = BouncerWeights {
            gas: tx_execution_info.actual_resources.get_builtin_count(constants::L1_GAS_USAGE),
            n_steps: tx_n_steps,
            message_segment_length: calc_message_segment_length(tx_execution_info, tx)?,
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
        self.transactional.available_capacity = self
            .transactional
            .available_capacity
            .checked_sub(tx_weights)
            .ok_or(TransactionExecutionError::BlockFull)?;
        Ok(())
    }

    fn update_used_state_entries_sets<S: StateReader>(
        &mut self,
        tx_execution_info: &TransactionExecutionInfo,
        state: &mut TransactionalState<'_, S>,
    ) -> TransactionExecutorResult<()> {
        // Count the marginal contribution to the executed_class_hashes
        self.transactional
            .executed_class_hashes
            .extend(tx_execution_info.get_executed_class_hashes());

        // Count the marginal contribution to the visited_storage_entries
        self.transactional
            .visited_storage_entries
            .extend(tx_execution_info.get_visited_storage_entries());

        // Count the marginal contribution to the state diff (w.r.t. the OS output encoding).
        let tx_state_changes_keys = state.get_actual_state_changes()?.into_keys();
        self.transactional.state_changes_keys =
            tx_state_changes_keys.difference(&self.parent.state_changes_keys);
        Ok(())
    }

    fn calc_n_steps_and_builtin_count<S: StateReader>(
        &self,
        execution_info_resources: &ResourcesMapping,
        state: &TransactionalState<'_, S>,
    ) -> TransactionExecutorResult<(usize, BuiltinCount)> {
        // Count the additional OS resources that are not present in the transaction exection info.
        let mut additional_os_resources = get_casm_hash_calculation_resources(
            state,
            &self.parent.executed_class_hashes,
            &self.transactional.executed_class_hashes,
        )?;
        additional_os_resources += &get_particia_update_resources(
            &self.parent.visited_storage_entries,
            &self.transactional.visited_storage_entries,
        )?;
        let additional_builtin_count =
            BuiltinCount::from(&ResourcesMapping(additional_os_resources.builtin_instance_counter));

        // Sum all the builtin resources.
        let execution_info_builtin_count = BuiltinCount::from(execution_info_resources);
        let builtin_count = execution_info_builtin_count + additional_builtin_count;

        // The n_steps counter also includes the count of memory holes.
        let n_steps = additional_os_resources.n_steps
            + execution_info_resources.get_builtin_count(constants::N_STEPS_RESOURCE)
            + additional_os_resources.n_memory_holes
            + execution_info_resources.get_builtin_count("n_memory_holes"); // TODO: Add a constant for "n_memory_holes".

        Ok((n_steps, builtin_count))
    }

    pub fn commit(mut self) -> Bouncer {
        self.parent.merge(self.transactional);
        self.parent
    }

    pub fn abort(self) -> Bouncer {
        self.parent
    }
}

// TODO: this is duplicate with the function in transaction_executor. remove on of them.
fn calc_message_segment_length(
    tx_execution_info: &TransactionExecutionInfo,
    tx: &Transaction,
) -> TransactionExecutorResult<usize> {
    let call_infos: IntoIter<&CallInfo> =
        [&tx_execution_info.validate_call_info, &tx_execution_info.execute_call_info]
            .iter()
            .filter_map(|&call_info| call_info.as_ref())
            .collect::<Vec<&CallInfo>>()
            .into_iter();
    let l1_handler_payload_size: Option<usize> =
        if let Transaction::L1HandlerTransaction(l1_handler_tx) = &tx {
            Some(l1_handler_tx.payload_size())
        } else {
            None
        };
    let msg_l1_cost_info = MessageL1CostInfo::calculate(call_infos, l1_handler_payload_size)?;
    Ok(msg_l1_cost_info.message_segment_length)
}
