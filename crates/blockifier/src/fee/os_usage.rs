use std::collections::{HashMap, HashSet};

use cairo_vm::vm::runners::builtin_runner;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use serde::Deserialize;
use strum::IntoEnumIterator;

use crate::execution::deprecated_syscalls::hint_processor::SyscallCounter;
use crate::execution::deprecated_syscalls::DeprecatedSyscallSelector;
use crate::fee::os_resources::OS_RESOURCES;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::transaction_types::TransactionType;

#[derive(Debug, Deserialize)]
pub struct OsResources {
    // Mapping from every syscall to its execution resources in the OS (e.g., amount of Cairo
    // steps).
    execute_syscalls: HashMap<DeprecatedSyscallSelector, VmExecutionResources>,
    // Mapping from every transaction to its extra execution resources in the OS,
    // i.e., resources that don't count during the execution itself.
    execute_txs_inner: HashMap<TransactionType, VmExecutionResources>,
}

impl OsResources {
    pub fn execute_txs_inner(&self) -> &HashMap<TransactionType, VmExecutionResources> {
        &self.execute_txs_inner
    }

    pub fn new(os_resources: String) -> Self {
        let os_resources_object: OsResources = serde_json::from_str(&os_resources)
            .expect("os_resources string cannot be deserialized.");
        os_resources_object._assert_resources_entries();
        os_resources_object._assert_resource_name_consistency();
        os_resources_object
    }

    fn _assert_resources_entries(&self) {
        for tx_type in TransactionType::iter() {
            assert!(self.execute_txs_inner.get(&tx_type).is_some());
        }
        for syscall_selector in DeprecatedSyscallSelector::iter() {
            assert!(self.execute_syscalls.get(&syscall_selector).is_some());
        }
    }

    fn _assert_resource_name_consistency(&self) {
        let known_builtin_names: HashSet<&str> = HashSet::from([
            builtin_runner::OUTPUT_BUILTIN_NAME,
            builtin_runner::HASH_BUILTIN_NAME,
            builtin_runner::RANGE_CHECK_BUILTIN_NAME,
            builtin_runner::SIGNATURE_BUILTIN_NAME,
            builtin_runner::BITWISE_BUILTIN_NAME,
            builtin_runner::EC_OP_BUILTIN_NAME,
            builtin_runner::KECCAK_BUILTIN_NAME,
            builtin_runner::POSEIDON_BUILTIN_NAME,
            builtin_runner::SEGMENT_ARENA_BUILTIN_NAME,
        ]);
        for resources in self.execute_syscalls.values().chain(self.execute_txs_inner.values()) {
            for builtin_name in resources.builtin_instance_counter.keys() {
                assert!(known_builtin_names.contains(builtin_name.as_str()));
            }
        }
    }
}

/// Calculates the additional resources needed for the OS to run the given syscalls;
/// i.e., the resources of the StarkNet OS function `execute_syscalls`.
pub fn get_additional_os_resources(
    syscall_counter: &SyscallCounter,
    tx_type: TransactionType,
) -> Result<VmExecutionResources, TransactionExecutionError> {
    let mut os_additional_vm_resources = VmExecutionResources::default();
    for (syscall_selector, count) in syscall_counter {
        let syscall_resources =
            OS_RESOURCES.execute_syscalls.get(syscall_selector).unwrap_or_else(|| {
                panic!("OS resources of syscall '{syscall_selector:?}' are unknown.")
            });
        os_additional_vm_resources += &(syscall_resources * *count);
    }

    // Calculates the additional resources needed for the OS to run the given transaction;
    // i.e., the resources of the StarkNet OS function `execute_transactions_inner`.
    // Also adds the resources needed for the fee transfer execution, performed in the end·
    // of every transaction.
    let os_resources = OS_RESOURCES
        .execute_txs_inner
        .get(&tx_type)
        .expect("`OS_RESOURCES` must contain all transaction types.");
    Ok(&os_additional_vm_resources + os_resources)
}
