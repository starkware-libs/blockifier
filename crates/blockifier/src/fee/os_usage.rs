use std::collections::HashMap;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use serde::Deserialize;

use crate::execution::deprecated_syscalls::hint_processor::SyscallCounter;
use crate::execution::deprecated_syscalls::DeprecatedSyscallSelector;
use crate::fee::os_resources::OS_RESOURCES;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::transaction_types::TransactionType;

#[cfg(test)]
#[path = "os_usage_test.rs"]
pub mod test;

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
