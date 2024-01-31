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
    pub fn resources_for_tx_type(&self, tx_type: &TransactionType) -> &VmExecutionResources {
        self.execute_txs_inner
            .get(tx_type)
            .unwrap_or_else(|| panic!("should contain transaction type '{tx_type:?}'."))
    }
}

// Calculates the additional resources needed for the OS to run the given transaction;
// i.e., the resources of the Starknet OS function `execute_transactions_inner`.
// Also adds the resources needed for the fee transfer execution, performed in the end·
// of every transaction.
pub fn get_additional_tx_type_os_resources(
    tx_type: TransactionType,
    _calldata_length: usize,
) -> Result<VmExecutionResources, TransactionExecutionError> {
    // TODO(Noa, 21/01/24): Use calldata_length.
    let os_additional_vm_resources = VmExecutionResources::default();
    let os_resources = OS_RESOURCES.resources_for_tx_type(&tx_type);
    Ok(&os_additional_vm_resources + os_resources)
}

/// Calculates the additional resources needed for the OS to run the given syscalls;
/// i.e., the resources of the Starknet OS function `execute_syscalls`.
pub fn get_entry_point_syscall_resources(
    syscall_counter: &SyscallCounter
) -> Result<VmExecutionResources, TransactionExecutionError> {
    let mut os_additional_vm_resources = VmExecutionResources::default();
    for (syscall_selector, count) in syscall_counter {
        let syscall_resources =
            OS_RESOURCES.execute_syscalls.get(syscall_selector).unwrap_or_else(|| {
                panic!("OS resources of syscall '{syscall_selector:?}' are unknown.")
            });
        os_additional_vm_resources += &(syscall_resources * *count);
    }
    Ok(os_additional_vm_resources)
}
