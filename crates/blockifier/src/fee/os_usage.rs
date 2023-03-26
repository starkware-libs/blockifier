use std::collections::HashMap;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use once_cell::sync::Lazy;

use crate::execution::errors::PostExecutionError;
use crate::transaction::objects::TransactionType;

#[cfg(test)]
#[path = "os_usage_test.rs"]
pub mod test;

pub struct OsResources {
    // Mapping from every syscall to its execution resources in the OS (e.g., amount of Cairo
    // steps).
    execute_syscalls: HashMap<&'static str, ExecutionResources>,
    // Mapping from every transaction to its extra execution resources in the OS,
    // i.e., resources that don't count during the execution itself.
    execute_txs_inner: HashMap<TransactionType, ExecutionResources>,
}

/// Shorthand for creating ExecutionResources instances.
fn execution_resources(n_steps: usize, n_rc: usize, n_pedersen: usize) -> ExecutionResources {
    ExecutionResources {
        n_steps,
        n_memory_holes: 0,
        builtin_instance_counter: HashMap::from([
            ("range_check_builtin".to_string(), n_rc),
            ("pedersen_builtin".to_string(), n_pedersen),
        ]),
    }
    .filter_unused_builtins()
}

pub static OS_RESOURCES: Lazy<OsResources> = Lazy::new(|| OsResources {
    execute_syscalls: HashMap::from([
        ("call_contract", execution_resources(630, 18, 0)),
        ("delegate_call", execution_resources(652, 18, 0)),
        ("delegate_l1_handler", execution_resources(631, 14, 0)),
        ("deploy", execution_resources(878, 17, 7)),
        ("emit_event", execution_resources(19, 0, 0)),
        ("get_block_number", execution_resources(40, 0, 0)),
        ("get_block_timestamp", execution_resources(38, 0, 0)),
        ("get_caller_address", execution_resources(32, 0, 0)),
        ("get_contract_address", execution_resources(36, 0, 0)),
        ("get_sequencer_address", execution_resources(34, 0, 0)),
        ("get_tx_info", execution_resources(29, 0, 0)),
        ("get_tx_signature", execution_resources(44, 0, 0)),
        ("library_call", execution_resources(619, 18, 0)),
        ("library_call_l1_handler", execution_resources(598, 14, 0)),
        ("replace_class", execution_resources(73, 0, 0)),
        ("send_message_to_l1", execution_resources(84, 0, 0)),
        ("storage_read", execution_resources(44, 0, 0)),
        ("storage_write", execution_resources(46, 0, 0)),
    ]),
    execute_txs_inner: HashMap::from([
        (TransactionType::Declare, execution_resources(2581, 61, 15)),
        (TransactionType::Deploy, execution_resources(0, 0, 0)),
        (TransactionType::DeployAccount, execution_resources(3434, 80, 23)),
        (TransactionType::InvokeFunction, execution_resources(3181, 77, 16)),
        (TransactionType::L1Handler, execution_resources(1006, 16, 11)),
    ]),
});

pub fn get_additional_os_resources(
    syscall_counter: HashMap<String, usize>,
    tx_type: TransactionType,
) -> Result<ExecutionResources, PostExecutionError> {
    // Calculate the additional resources needed for the OS to run the given syscalls;
    // i.e., the resources of the function execute_syscalls().
    let mut os_additional_resources = execution_resources(0, 0, 0);
    for (syscall_name, count) in syscall_counter {
        match OS_RESOURCES.execute_syscalls.get(syscall_name.as_str()) {
            Some(syscall_resources) => {
                os_additional_resources += &(&syscall_resources.clone() * count);
            }
            None => return Err(PostExecutionError::UnknownSyscallResources(syscall_name)),
        }
    }

    // Calculate the additional resources needed for the OS to run the given transaction;
    // i.e., the resources of the StarkNet OS function execute_transactions_inner().
    Ok(&os_additional_resources + OS_RESOURCES.execute_txs_inner.get(&tx_type).unwrap())
}
