use std::collections::HashMap;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use lazy_static::lazy_static;

#[derive(Eq, Hash, PartialEq)]
pub enum TransactionType {
    Declare,
    Deploy,
    DeployAccount,
    InitializeBlockInfo,
    InvokeFunction,
    L1Handler,
}

pub struct OsResources {
    // Mapping from every syscall to its execution resources in the OS (e.g., amount of Cairo
    // steps).
    execute_syscalls: HashMap<String, ExecutionResources>,
    // Mapping from every transaction to its extra execution resources in the OS,
    // i.e., resources that don't count during the execution itself.
    execute_txs_inner: HashMap<TransactionType, ExecutionResources>,
}

/// Shorthand for creating ExecutionResources instances.
fn exec_resources(n_steps: usize, n_rc: usize, n_pedersen: usize) -> ExecutionResources {
    ExecutionResources {
        n_steps,
        n_memory_holes: 0,
        builtin_instance_counter: {
            let mut instance_counter = HashMap::new();
            instance_counter.insert("range_check_builtin".to_string(), n_rc);
            instance_counter.insert("pedersen_builtin".to_string(), n_pedersen);
            instance_counter
        },
    }
    .filter_unused_builtins()
}

lazy_static! {
    static ref OS_RESOURCES: OsResources = {
        let mut execute_syscalls = HashMap::new();
        let mut execute_txs_inner = HashMap::new();

        execute_syscalls.insert("call_contract".to_string(), exec_resources(630, 18, 0));
        execute_syscalls.insert("delegate_call".to_string(), exec_resources(652, 18, 0));
        execute_syscalls.insert("delegate_l1_handler".to_string(), exec_resources(631, 14, 0));
        execute_syscalls.insert("deploy".to_string(), exec_resources(878, 17, 7));
        execute_syscalls.insert("emit_event".to_string(), exec_resources(19, 0, 0));
        execute_syscalls.insert("get_block_number".to_string(), exec_resources(40, 0, 0));
        execute_syscalls.insert("get_block_timestamp".to_string(), exec_resources(38, 0, 0));
        execute_syscalls.insert("get_caller_address".to_string(), exec_resources(32, 0, 0));
        execute_syscalls.insert("get_contract_address".to_string(), exec_resources(36, 0, 0));
        execute_syscalls.insert("get_sequencer_address".to_string(), exec_resources(34, 0, 0));
        execute_syscalls.insert("get_tx_info".to_string(), exec_resources(29, 0, 0));
        execute_syscalls.insert("get_tx_signature".to_string(), exec_resources(44, 0, 0));
        execute_syscalls.insert("library_call".to_string(), exec_resources(619, 18, 0));
        execute_syscalls.insert("library_call_l1_handler".to_string(), exec_resources(598, 14, 0));
        execute_syscalls.insert("replace_class".to_string(), exec_resources(73, 0, 0));
        execute_syscalls.insert("send_message_to_l1".to_string(), exec_resources(84, 0, 0));
        execute_syscalls.insert("storage_read".to_string(), exec_resources(44, 0, 0));
        execute_syscalls.insert("storage_write".to_string(), exec_resources(46, 0, 0));

        execute_txs_inner.insert(TransactionType::Declare, exec_resources(2581, 61, 15));
        execute_txs_inner.insert(TransactionType::Deploy, exec_resources(0, 0, 0));
        execute_txs_inner.insert(TransactionType::DeployAccount, exec_resources(3434, 80, 23));
        execute_txs_inner.insert(TransactionType::InvokeFunction, exec_resources(3181, 77, 16));
        execute_txs_inner.insert(TransactionType::L1Handler, exec_resources(1006, 16, 11));

        OsResources { execute_syscalls, execute_txs_inner }
    };
}

pub fn get_additional_os_resources(
    syscall_counter: HashMap<String, usize>,
    tx_type: TransactionType,
) -> ExecutionResources {
    // Calculate the additional resources needed for the OS to run the given syscalls;
    // i.e., the resources of the function execute_syscalls().
    let mut os_additional_resources = exec_resources(0, 0, 0);
    for (syscall_name, count) in syscall_counter {
        // TODO(Dori, 1/5/2023): Use `+=` when available.
        os_additional_resources = os_additional_resources
            + (OS_RESOURCES.execute_syscalls.get(&syscall_name).unwrap().clone() * count);
    }

    // Calculate the additional resources needed for the OS to run the given transaction;
    // i.e., the resources of the StarkNet OS function execute_transactions_inner().
    os_additional_resources + OS_RESOURCES.execute_txs_inner.get(&tx_type).unwrap().clone()
}
