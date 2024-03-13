use std::collections::HashSet;

use serde::Deserialize;
use starknet_api::core::ClassHash;

use crate::blockifier::transaction_executor::TransactionExecutorResult;
use crate::execution::call_info::{ExecutionSummary, MessageL1CostInfo};
use crate::fee::gas_usage::{get_message_segment_length, get_messages_gas_usage};
use crate::state::cached_state::{StateChangesKeys, StorageEntry, TransactionalState};
use crate::state::state_api::StateReader;
use crate::transaction::objects::GasVector;

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

#[derive(Clone, Copy, Debug, Default, derive_more::Sub, Deserialize, PartialEq)]
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

    // TODO update function (in the next PR)

    pub fn update_auxiliary_info<S: StateReader>(
        &mut self,
        tx_execution_summary: &ExecutionSummary,
        state: &mut TransactionalState<'_, S>,
    ) -> TransactionExecutorResult<()> {
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
/// Returns the total message segment length and the L1 gas usage.
pub fn calc_message_l1_resources(
    execution_summary: &ExecutionSummary,
    l1_handler_payload_size: Option<usize>,
) -> (usize, GasVector) {
    let message_segment_length = get_message_segment_length(
        &execution_summary.l2_to_l1_payload_lengths,
        l1_handler_payload_size,
    );
    let gas_usage = get_messages_gas_usage(
        &MessageL1CostInfo {
            l2_to_l1_payload_lengths: execution_summary.l2_to_l1_payload_lengths.clone(),
            message_segment_length,
        },
        l1_handler_payload_size,
    );
    (message_segment_length, gas_usage)
}
