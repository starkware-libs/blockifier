use std::collections::{HashMap, HashSet};

use cairo_vm::vm::runners::builtin_runner;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use serde::Deserialize;
use strum::IntoEnumIterator;
use thiserror::Error;

use crate::execution::deprecated_syscalls::hint_processor::SyscallCounter;
use crate::execution::deprecated_syscalls::DeprecatedSyscallSelector;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::transaction_types::TransactionType;

const KNOWN_BUILTIN_NAMES: [&str; 9] = [
    builtin_runner::OUTPUT_BUILTIN_NAME,
    builtin_runner::HASH_BUILTIN_NAME,
    builtin_runner::RANGE_CHECK_BUILTIN_NAME,
    builtin_runner::SIGNATURE_BUILTIN_NAME,
    builtin_runner::BITWISE_BUILTIN_NAME,
    builtin_runner::EC_OP_BUILTIN_NAME,
    builtin_runner::KECCAK_BUILTIN_NAME,
    builtin_runner::POSEIDON_BUILTIN_NAME,
    builtin_runner::SEGMENT_ARENA_BUILTIN_NAME,
];

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
    pub fn new(os_resources: String) -> Result<Self, OsResourcesError> {
        let os_resources: OsResources = serde_json::from_str(&os_resources)?;

        // Run Validations.
        os_resources.validate_execute_syscalls_contain_all_syscall_selectors()?;
        os_resources.validate_execute_txs_inner_contains_all_tx_types()?;
        os_resources.validate_known_builtins()?;

        Ok(os_resources)
    }

    pub fn execute_txs_inner(&self) -> &HashMap<TransactionType, VmExecutionResources> {
        &self.execute_txs_inner
    }

    pub fn resources_for_tx_type(&self, tx_type: &TransactionType) -> &VmExecutionResources {
        self.execute_txs_inner
            .get(tx_type)
            .unwrap_or_else(|| panic!("should contain transaction type '{tx_type:?}'."))
    }

    // Validations.

    fn validate_execute_syscalls_contain_all_syscall_selectors(
        &self,
    ) -> Result<(), OsResourcesError> {
        let missing_variants: Vec<DeprecatedSyscallSelector> = DeprecatedSyscallSelector::iter()
            .filter(|variant| !self.execute_syscalls.contains_key(variant))
            .collect();

        if missing_variants.is_empty() {
            Ok(())
        } else {
            Err(OsResourcesError::ValidationError(format!(
                "os_resources.execute_syscalls missing syscall selectors: {:?}",
                missing_variants
            )))
        }
    }

    fn validate_execute_txs_inner_contains_all_tx_types(&self) -> Result<(), OsResourcesError> {
        let missing_variants: Vec<TransactionType> = TransactionType::iter()
            .filter(|variant| !self.execute_txs_inner.contains_key(variant))
            .collect();

        if missing_variants.is_empty() {
            Ok(())
        } else {
            Err(OsResourcesError::ValidationError(format!(
                "os_resources.execute_txs_inner missing transaction types: {:?}",
                missing_variants
            )))
        }
    }

    fn validate_known_builtins(&self) -> Result<(), OsResourcesError> {
        let builtins: HashSet<&str> = self
            .execute_syscalls
            .values()
            .chain(self.execute_txs_inner.values())
            .flat_map(|resources| resources.builtin_instance_counter.keys())
            .map(|s| s.as_str())
            .collect();

        let unknown_builtins: HashSet<&str> =
            builtins.difference(&KNOWN_BUILTIN_NAMES.iter().cloned().collect()).cloned().collect();

        if unknown_builtins.is_empty() {
            Ok(())
        } else {
            Err(OsResourcesError::ValidationError(format!(
                "Os resources includes unrecognized builtins: {unknown_builtins:?}",
            )))
        }
    }
}

/// Calculates the additional resources needed for the OS to run the given syscalls;
/// i.e., the resources of the StarkNet OS function `execute_syscalls`.
pub fn get_additional_os_resources(
    syscall_counter: &SyscallCounter,
    tx_type: TransactionType,
    os_resources: &OsResources,
) -> Result<VmExecutionResources, TransactionExecutionError> {
    let mut os_additional_vm_resources = VmExecutionResources::default();
    for (syscall_selector, count) in syscall_counter {
        let syscall_resources = os_resources
            .execute_syscalls
            .get(syscall_selector)
            .unwrap_or_else(|| panic!("Should contain syscall selector '{syscall_selector:?}'."));
        os_additional_vm_resources += &(syscall_resources * *count);
    }

    // Calculates the additional resources needed for the OS to run the given transaction;
    // i.e., the resources of the StarkNet OS function `execute_transactions_inner`.
    // Also adds the resources needed for the fee transfer execution, performed in the end·
    // of every transaction.
    let os_resources_for_tx_type = os_resources.resources_for_tx_type(&tx_type);
    Ok(&os_additional_vm_resources + os_resources_for_tx_type)
}

#[derive(Debug, Error)]
pub enum OsResourcesError {
    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),
    #[error("{0}")]
    ValidationError(String),
}
