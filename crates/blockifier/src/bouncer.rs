use std::collections::HashSet;

use serde::Deserialize;
use starknet_api::core::ClassHash;

use crate::blockifier::transaction_executor::TransactionExecutorResult;
use crate::state::cached_state::{StateChangesKeys, StorageEntry, TransactionalState};
use crate::state::state_api::StateReader;
use crate::transaction::objects::TransactionExecutionInfo;

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
    output: usize,
    pedersen: usize,
    poseidon: usize,
    range_check: usize,
    segment_arena: usize, // TODO - is this needed? was not includeded in the original bouncer.
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
    pub capacity: BouncerWeights,
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

    pub fn create_transactional(self) -> TransactionBouncer {
        TransactionBouncer::new(self)
    }

    pub fn merge(&mut self, other: Bouncer) {
        self.executed_class_hashes.extend(other.executed_class_hashes);
        self.state_changes_keys.extend(&other.state_changes_keys);
        self.visited_storage_entries.extend(other.visited_storage_entries);
        self.capacity = other.capacity;
    }
}

#[derive(Clone)]
pub struct TransactionBouncer {
    // The parent bouncer can be modified only through the merge method.
    parent: Bouncer,
    // The transactional bouncer can be modified only through the update method.
    transactional: Bouncer,
}

impl TransactionBouncer {
    pub fn new(parent: Bouncer) -> TransactionBouncer {
        let capacity = parent.capacity;
        TransactionBouncer { parent, transactional: Bouncer::new(capacity) }
    }

    // TODO update function (in the next PR)

    pub fn update_used_state_entries_sets<S: StateReader>(
        &mut self,
        tx_execution_info: &TransactionExecutionInfo,
        state: &mut TransactionalState<'_, S>,
    ) -> TransactionExecutorResult<()> {
        self.transactional
            .executed_class_hashes
            .extend(tx_execution_info.get_executed_class_hashes());
        self.transactional
            .visited_storage_entries
            .extend(tx_execution_info.get_visited_storage_entries());
        let tx_state_changes_keys = state.get_actual_state_changes()?.into_keys();
        self.transactional.state_changes_keys =
            tx_state_changes_keys.difference(&self.parent.state_changes_keys);
        Ok(())
    }

    pub fn commit(mut self) -> Bouncer {
        self.parent.merge(self.transactional);
        self.parent
    }

    pub fn abort(self) -> Bouncer {
        self.parent
    }
}
