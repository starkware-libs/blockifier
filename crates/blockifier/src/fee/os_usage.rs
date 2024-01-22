use std::collections::HashMap;
use std::str::FromStr;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use serde::Deserialize;
use strum_macros::EnumIter;

use crate::execution::deprecated_syscalls::hint_processor::SyscallCounter;
use crate::execution::deprecated_syscalls::DeprecatedSyscallSelector;
use crate::fee::os_resources::OS_RESOURCES;
use crate::transaction::errors::{ParseError, TransactionExecutionError};
use crate::transaction::transaction_types::TransactionType;

#[cfg(test)]
#[path = "os_usage_test.rs"]
pub mod test;

#[derive(Clone, Copy, Debug, Deserialize, EnumIter, Eq, Hash, PartialEq)]
pub enum ResourcesRole {
    Constant,
    Slope,
}

impl FromStr for ResourcesRole {
    type Err = ParseError;

    fn from_str(resources_role: &str) -> Result<Self, Self::Err> {
        match resources_role {
            "Constant" => Ok(ResourcesRole::Constant),
            "Slope" => Ok(ResourcesRole::Slope),
            unknown_resources_role => {
                Err(ParseError::UnknownTransactionType(unknown_resources_role.to_string()))
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct OsResources {
    // Mapping from every syscall to its execution resources in the OS (e.g., amount of Cairo
    // steps).
    execute_syscalls: HashMap<DeprecatedSyscallSelector, VmExecutionResources>,
    // Mapping from every transaction to its extra execution resources in the OS,
    // i.e., resources that don't count during the execution itself.
    execute_txs_inner: HashMap<TransactionType, HashMap<ResourcesRole, VmExecutionResources>>,
}

impl OsResources {
    fn resources_for_tx_type_by_resource_role(
        &self,
        tx_type: &TransactionType,
        resources_role: &ResourcesRole,
    ) -> &VmExecutionResources {
        self.execute_txs_inner
            .get(tx_type)
            .unwrap_or_else(|| panic!("should contain transaction type '{tx_type:?}'."))
            .get(resources_role)
            .unwrap_or_else(|| panic!("should contain constant resources '{resources_role:?}'."))
    }

    pub fn resources_for_tx_type(
        &self,
        tx_type: &TransactionType,
        calldata_length: usize,
    ) -> VmExecutionResources {
        self.resources_for_tx_type_by_resource_role(tx_type, &ResourcesRole::Constant)
            + &(OS_RESOURCES.resources_for_tx_type_by_resource_role(tx_type, &ResourcesRole::Slope)
                * calldata_length)
    }
}

/// Calculates the additional resources needed for the OS to run the given syscalls;
/// i.e., the resources of the Starknet OS function `execute_syscalls`.
pub fn get_additional_os_resources(
    syscall_counter: &SyscallCounter,
    tx_type: TransactionType,
    calldata_length: usize,
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
    // i.e., the resources of the Starknet OS function `execute_transactions_inner`.
    // Also adds the resources needed for the fee transfer execution, performed in the end·
    // of every transaction.
    let os_resources = OS_RESOURCES.resources_for_tx_type(&tx_type, calldata_length);
    Ok(&os_additional_vm_resources + &os_resources)
}
