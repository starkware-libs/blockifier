use std::collections::HashSet;

use cairo_vm::serde::deserialize_program::BuiltinName;
use derive_more::Add;
use serde::Deserialize;
use starknet_api::core::ClassHash;

use crate::abi::constants;
use crate::blockifier::bouncer::BouncerInfo;
use crate::blockifier::transaction_executor::{
    calc_message_segment_length, get_casm_hash_calculation_resources,
    get_particia_update_resources, TransactionExecutorResult,
};
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

    pub fn tmp_max() -> Self {
        Self {
            gas: 5000000,
            n_steps: 20000000,
            message_segment_length: 3750,
            state_diff_size: 20000,
            n_events: 10000,
            builtin_count: BuiltinCount::tmp_max(),
        }
    }
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

impl From<&ResourcesMapping> for BuiltinCount {
    fn from(resource_mapping: &ResourcesMapping) -> Self {
        Self {
            bitwise: resource_mapping.get_builtin_count(BuiltinName::bitwise.name()),
            ecdsa: resource_mapping.get_builtin_count(BuiltinName::ecdsa.name()),
            ec_op: resource_mapping.get_builtin_count(BuiltinName::ec_op.name()),
            keccak: resource_mapping.get_builtin_count(BuiltinName::keccak.name()),
            output: resource_mapping.get_builtin_count(BuiltinName::output.name()),
            pedersen: resource_mapping.get_builtin_count(BuiltinName::pedersen.name()),
            poseidon: resource_mapping.get_builtin_count(BuiltinName::poseidon.name()),
            range_check: resource_mapping.get_builtin_count(BuiltinName::range_check.name()),
        }
    }
}

impl BuiltinCount {
    impl_checked_sub!(bitwise, ecdsa, ec_op, keccak, output, pedersen, poseidon, range_check);

    pub fn tmp_max() -> Self {
        Self {
            bitwise: 39062,
            ecdsa: 1220,
            ec_op: 2441,
            keccak: 0,
            output: 0,
            pedersen: 78125,
            poseidon: 78125,
            range_check: 156250,
        }
    }
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

    pub fn create_transactional<'a>(&'a self) -> TransactionBouncer {
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
pub struct TransactionBouncer<'a> {
    // The parent bouncer can only be modified by merging the transactional bouncer into it.
    parent: &'a Bouncer,
    // The transactional bouncer is modified according to the transaction execution.
    transactional: Bouncer,
}

impl<'a> TransactionBouncer<'a> {
    pub fn new(parent: &'a Bouncer) -> TransactionBouncer {
        let transactional = Bouncer::new(parent.available_capacity, parent.max_capacity);
        TransactionBouncer { parent, transactional }
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
            get_onchain_data_segment_length(self.transactional.state_changes_keys.count());
        let message_segment_length =
            calc_message_segment_length(tx_execution_info, l1_handler_payload_size)?;

        let tx_weights = BouncerWeights {
            gas: tx_execution_info.actual_resources.get_builtin_count(constants::L1_GAS_USAGE),
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

        println!("yael additional_os_resources {:?}", additional_os_resources);

        let additional_builtin_count =
            BuiltinCount::from(&ResourcesMapping(additional_os_resources.builtin_instance_counter));

        println!("yael additional_builtin_count {:?}", additional_builtin_count);

        // Sum all the builtin resources.
        let execution_info_builtin_count = BuiltinCount::from(execution_info_resources);
        println!("yael execution_info_builtin_count {:?}", execution_info_builtin_count);
        let builtin_count = execution_info_builtin_count + additional_builtin_count;
        println!("yael builtin_count {:?}", builtin_count);

        // The n_steps counter also includes the count of memory holes.
        let n_steps = additional_os_resources.n_steps
            + execution_info_resources.get_builtin_count(constants::N_STEPS_RESOURCE)
            + additional_os_resources.n_memory_holes
            + execution_info_resources.get_builtin_count("n_memory_holes"); // TODO: Add a constant for "n_memory_holes".

        Ok((n_steps, builtin_count))
    }

    pub fn commit(mut self) -> &'a Bouncer {
        self.parent.merge(self.transactional);
        self.parent
    }

    pub fn abort(self) -> &'a Bouncer {
        self.parent
    }

    pub fn compare_bouncer_results(
        &self,
        bouncer_info: &BouncerInfo,
        tx_executed_class_hashes: &HashSet<ClassHash>,
        tx_visited_storage_entries: &HashSet<StorageEntry>,
        tx_unique_state_changes_keys: &StateChangesKeys,
    ) {
        println!("yael Bouncer Info {:?}", bouncer_info);
        println!(
            "yael Bouncer parent-transactional {:?}",
            self.parent.available_capacity - self.transactional.available_capacity
        );
        println!(
            "yael tx_executed_class_hashes {:?}, new : {:?}",
            tx_executed_class_hashes, self.transactional.executed_class_hashes
        );
        println!(
            "yael tx_visited_storage_entries {:?}, new : {:?}",
            tx_visited_storage_entries, self.transactional.visited_storage_entries
        );
        println!(
            "yael tx_unique_state_changes_keys {:?}, new : {:?}",
            tx_unique_state_changes_keys, self.transactional.state_changes_keys
        );

        assert_eq!(
            tx_executed_class_hashes, &self.transactional.executed_class_hashes,
            "yael error in executed_class_hashes"
        );
        assert_eq!(
            tx_visited_storage_entries, &self.transactional.visited_storage_entries,
            "yael error in visited_storage_entries"
        );
        assert_eq!(
            tx_unique_state_changes_keys, &self.transactional.state_changes_keys,
            "yael error in state_changes_keys"
        );

        assert_eq!(
            bouncer_info.gas_weight,
            self.parent.available_capacity.gas - self.transactional.available_capacity.gas,
            "yael error in gas_weight"
        );
        assert_eq!(
            bouncer_info.message_segment_length,
            self.parent.available_capacity.message_segment_length
                - self.transactional.available_capacity.message_segment_length,
            "yael error in message_segment_length"
        );
        assert_eq!(
            bouncer_info.state_diff_size,
            self.parent.available_capacity.state_diff_size
                - self.transactional.available_capacity.state_diff_size,
            "yael error in state_diff_size"
        );
        assert_eq!(
            bouncer_info.n_events,
            self.parent.available_capacity.n_events
                - self.transactional.available_capacity.n_events,
            "yael error in n_events"
        );
        assert_eq!(
            bouncer_info.execution_resources.n_steps,
            self.parent.available_capacity.n_steps - self.transactional.available_capacity.n_steps,
            "yael error in n_steps"
        );
        assert_eq!(
            *bouncer_info
                .execution_resources
                .builtin_instance_counter
                .get(BuiltinName::bitwise.name())
                .unwrap(),
            self.parent.available_capacity.builtin_count.bitwise
                - self.transactional.available_capacity.builtin_count.bitwise,
            "yael error in bitwise"
        );
        assert_eq!(
            *bouncer_info
                .execution_resources
                .builtin_instance_counter
                .get(BuiltinName::ecdsa.name())
                .unwrap(),
            self.parent.available_capacity.builtin_count.ecdsa
                - self.transactional.available_capacity.builtin_count.ecdsa,
            "yael error in ecdsa"
        );
        assert_eq!(
            *bouncer_info
                .execution_resources
                .builtin_instance_counter
                .get(BuiltinName::ec_op.name())
                .unwrap(),
            self.parent.available_capacity.builtin_count.ec_op
                - self.transactional.available_capacity.builtin_count.ec_op,
            "yael error in ec_op"
        );
        assert_eq!(
            *bouncer_info
                .execution_resources
                .builtin_instance_counter
                .get(BuiltinName::keccak.name())
                .unwrap(),
            self.parent.available_capacity.builtin_count.keccak
                - self.transactional.available_capacity.builtin_count.keccak,
            "yael error in keccak"
        );
        assert_eq!(
            *bouncer_info
                .execution_resources
                .builtin_instance_counter
                .get(BuiltinName::output.name())
                .unwrap(),
            self.parent.available_capacity.builtin_count.output
                - self.transactional.available_capacity.builtin_count.output,
            "yael error in output"
        );
        assert_eq!(
            *bouncer_info
                .execution_resources
                .builtin_instance_counter
                .get(BuiltinName::pedersen.name())
                .unwrap(),
            self.parent.available_capacity.builtin_count.pedersen
                - self.transactional.available_capacity.builtin_count.pedersen,
            "yael error in pedersen"
        );
        assert_eq!(
            *bouncer_info
                .execution_resources
                .builtin_instance_counter
                .get(BuiltinName::poseidon.name())
                .unwrap(),
            self.parent.available_capacity.builtin_count.poseidon
                - self.transactional.available_capacity.builtin_count.poseidon,
            "yael error in poseidon"
        );
        assert_eq!(
            *bouncer_info
                .execution_resources
                .builtin_instance_counter
                .get(BuiltinName::range_check.name())
                .unwrap(),
            self.parent.available_capacity.builtin_count.range_check
                - self.transactional.available_capacity.builtin_count.range_check,
            "yael error in range_check"
        );
    }
}
