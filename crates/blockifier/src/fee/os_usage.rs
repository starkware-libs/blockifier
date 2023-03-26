use std::collections::HashMap;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use once_cell::sync::Lazy;
use serde::Deserialize;

use crate::execution::syscall_handling::SyscallCounter;
use crate::execution::syscalls::SyscallSelector;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::transaction_types::TransactionType;

#[cfg(test)]
#[path = "os_usage_test.rs"]
pub mod test;

#[derive(Deserialize)]
pub struct OsResources {
    // Mapping from every syscall to its execution resources in the OS (e.g., amount of Cairo
    // steps).
    execute_syscalls: HashMap<SyscallSelector, ExecutionResources>,
    // Mapping from every transaction to its extra execution resources in the OS,
    // i.e., resources that don't count during the execution itself.
    execute_txs_inner: HashMap<TransactionType, ExecutionResources>,
}

// Filename can't be a static string because `include_str!` macro won't work.
macro_rules! os_resources_filename {
    () => {
        "os_resources.json"
    };
}
pub static OS_RESOURCES: Lazy<OsResources> = Lazy::new(|| {
    serde_json::from_str(include_str!(os_resources_filename!())).expect(
        format!("{} either does not exist or cannot be deserialized.", os_resources_filename!())
            .as_str(),
    )
});

pub fn get_additional_os_resources(
    syscall_counter: SyscallCounter,
    tx_type: TransactionType,
) -> Result<ExecutionResources, TransactionExecutionError> {
    // Calculate the additional resources needed for the OS to run the given syscalls;
    // i.e., the resources of the function execute_syscalls().
    let mut os_additional_resources = ExecutionResources::default();
    for (syscall, count) in syscall_counter {
        let syscall_resources = OS_RESOURCES
            .execute_syscalls
            .get(&syscall)
            .unwrap_or_else(|| panic!("OS resources of syscall '{:?}' are unknown.", syscall));
        os_additional_resources += &(syscall_resources * count);
    }

    // Calculate the additional resources needed for the OS to run the given transaction;
    // i.e., the resources of the StarkNet OS function execute_transactions_inner().
    Ok(&os_additional_resources
        + OS_RESOURCES.execute_txs_inner.get(&tx_type).expect(
            format!("{} must contain all transaction types.", os_resources_filename!()).as_str(),
        ))
}
