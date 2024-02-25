use std::collections::HashSet;

use cairo_vm::serde::deserialize_program::BuiltinName;
use derive_more::Add;
use serde::Deserialize;
use starknet_api::core::ClassHash;

use crate::abi::constants;
use crate::blockifier::transaction_executor::{
    get_casm_hash_calculation_resources, get_particia_update_resources, TransactionExecutorResult,
};
use crate::state::cached_state::{StateChangesKeys, StorageEntry, TransactionalState};
use crate::state::state_api::StateReader;
use crate::transaction::objects::ResourcesMapping;

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
    // The parent bouncer can be modified only through the merge method.
    parent: Bouncer,
    // The transactional bouncer can be modified only through the update method.
    child: Bouncer,
}

impl TransactionalBouncer {
    pub fn new(parent: Bouncer) -> TransactionalBouncer {
        let capacity = parent.capacity;
        TransactionalBouncer { parent, child: Bouncer::new(capacity) }
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

    pub fn commit(mut self) -> Bouncer {
        self.parent.merge(self.child);
        self.parent
    }

    pub fn abort(self) -> Bouncer {
        self.parent
    }
}
