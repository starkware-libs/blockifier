use std::collections::HashSet;

use serde::Deserialize;
use starknet_api::core::ClassHash;

use crate::state::cached_state::StorageEntry;

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
    gas: u64,
    n_steps: u64,
    message_segment_length: u64,
    state_diff_size: u64,
    builtin_count: BuiltinCount,
}

impl BouncerWeights {
    impl_checked_sub!(gas, n_steps, message_segment_length, state_diff_size, builtin_count);
}

#[derive(Clone, Copy, Debug, Default, derive_more::Sub, Deserialize, PartialEq)]
pub struct BuiltinCount {
    bitwise: u64,
    ecdsa: u64,
    ec_op: u64,
    keccak: u64,
    output: u64,
    pedersen: u64,
    poseidon: u64,
    range_check: u64,
}

impl BuiltinCount {
    impl_checked_sub!(bitwise, ecdsa, ec_op, keccak, output, pedersen, poseidon, range_check);
}

#[derive(Clone)]
pub struct Bouncer {
    executed_class_hashes: HashSet<ClassHash>,
    visited_storage_entries: HashSet<StorageEntry>,
    capacity: BouncerWeights,
}

impl Bouncer {
    pub fn new(capacity: BouncerWeights) -> Self {
        Bouncer {
            executed_class_hashes: HashSet::new(),
            visited_storage_entries: HashSet::new(),
            capacity,
        }
    }

    pub fn create_transactional(self) -> TransactionBouncer {
        TransactionBouncer::new(self)
    }

    pub fn merge(&mut self, other: Bouncer) {
        self.executed_class_hashes.extend(other.executed_class_hashes);
        self.visited_storage_entries.extend(other.visited_storage_entries);
        self.capacity = other.capacity;
    }
}

#[derive(Clone)]
pub struct TransactionBouncer {
    parent: Bouncer,
    transactional: Bouncer,
}

impl TransactionBouncer {
    pub fn new(parent: Bouncer) -> TransactionBouncer {
        let capacity = parent.capacity;
        TransactionBouncer { parent, transactional: Bouncer::new(capacity) }
    }

    // TODO update function (in the next PR)

    pub fn commit(mut self) -> Bouncer {
        self.parent.merge(self.transactional);
        self.parent
    }

    pub fn abort(self) -> Bouncer {
        self.parent
    }
}
