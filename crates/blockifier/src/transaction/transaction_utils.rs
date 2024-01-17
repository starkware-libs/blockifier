use std::collections::HashMap;

use cairo_vm::vm::runners::builtin_runner::SEGMENT_ARENA_BUILTIN_NAME;
use starknet_api::transaction::TransactionVersion;

use crate::abi::constants;
use crate::execution::call_info::CallInfo;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::ExecutionResources;
use crate::fee::os_usage::get_additional_os_resources;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionResult};
use crate::transaction::transaction_types::TransactionType;

/// Calculates the total resources needed to include the transaction in a Starknet block as
/// most-recent (recent w.r.t. application on the given state).
/// I.e., Cairo VM execution resources.
pub fn calculate_tx_resources(
    execution_resources: &ExecutionResources,
    l1_gas_usage_without_data: usize,
    l1_gas_usage_data: usize,
    tx_type: TransactionType,
) -> TransactionExecutionResult<ResourcesMapping> {
    // Add additional Cairo resources needed for the OS to run the transaction.
    let total_vm_usage = &execution_resources.vm_resources
        + &get_additional_os_resources(&execution_resources.syscall_counter, tx_type)?;
    let mut total_vm_usage = total_vm_usage.filter_unused_builtins();
    // The segment arena" builtin is not part of SHARP (not in any proof layout).
    // Each instance requires approximately 10 steps in the OS.
    // TODO(Noa, 01/07/23): Verify the removal of the segmen_arena builtin.
    let n_steps = total_vm_usage.n_steps
        + 10 * total_vm_usage
            .builtin_instance_counter
            .remove(SEGMENT_ARENA_BUILTIN_NAME)
            .unwrap_or_default();

    let mut tx_resources = HashMap::from([
        (constants::GAS_USAGE.to_string(), l1_gas_usage_without_data),
        (constants::DATA_GAS_USAGE.to_string(), l1_gas_usage_data),
        (constants::N_STEPS_RESOURCE.to_string(), n_steps + total_vm_usage.n_memory_holes),
    ]);
    tx_resources.extend(total_vm_usage.builtin_instance_counter);

    Ok(ResourcesMapping(tx_resources))
}

pub fn update_remaining_gas(remaining_gas: &mut u64, call_info: &CallInfo) {
    *remaining_gas -= call_info.execution.gas_consumed;
}

pub fn verify_contract_class_version(
    contract_class: ContractClass,
    declare_version: TransactionVersion,
) -> Result<ContractClass, TransactionExecutionError> {
    match contract_class {
        ContractClass::V0(_) => {
            if let TransactionVersion::ZERO | TransactionVersion::ONE = declare_version {
                Ok(contract_class)
            } else {
                Err(TransactionExecutionError::ContractClassVersionMismatch {
                    declare_version,
                    cairo_version: 0,
                })
            }
        }
        ContractClass::V1(_) => {
            if let TransactionVersion::TWO | TransactionVersion::THREE = declare_version {
                Ok(contract_class)
            } else {
                Err(TransactionExecutionError::ContractClassVersionMismatch {
                    declare_version,
                    cairo_version: 1,
                })
            }
        }
    }
}
