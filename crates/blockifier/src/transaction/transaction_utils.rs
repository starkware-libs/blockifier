use std::collections::HashMap;

use cairo_vm::vm::runners::builtin_runner::SEGMENT_ARENA_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use starknet_api::transaction::TransactionVersion;

use crate::abi::constants;
use crate::execution::call_info::CallInfo;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::ExecutionResources;
use crate::fee::os_usage::get_additional_os_resources;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{GasVector, ResourcesMapping, TransactionExecutionResult};
use crate::transaction::transaction_types::TransactionType;
use crate::utils::{merge_hashmaps, usize_from_u128};

/// Calculates the total resources needed to include the transaction in a Starknet block as
/// most-recent (recent w.r.t. application on the given state).
/// I.e., Cairo VM execution resources.
pub fn calculate_tx_resources(
    execution_resources: &ExecutionResources,
    gas_vector: GasVector,
    tx_type: TransactionType,
    calldata_length: usize,
) -> TransactionExecutionResult<ResourcesMapping> {
    let l1_gas_usage = usize_from_u128(gas_vector.l1_gas)
        .expect("This conversion should not fail as the value is a converted usize.");
    let l1_blob_gas_usage = usize_from_u128(gas_vector.l1_data_gas)
        .expect("This conversion should not fail as the value is a converted usize.");
    // Add additional Cairo resources needed for the OS to run the transaction.
    let total_vm_usage = &execution_resources.vm_resources
        + &get_additional_os_resources(
            &execution_resources.syscall_counter,
            tx_type,
            calldata_length,
        )?;
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
        (constants::L1_GAS_USAGE.to_string(), l1_gas_usage),
        (constants::BLOB_GAS_USAGE.to_string(), l1_blob_gas_usage),
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

// TODO(Ayelet, 01/02/2024): Move to VmExecutionResourcesWrapper when merged.
pub fn vm_execution_resources_to_hash_map(
    execution_resources: VmExecutionResources,
) -> HashMap<String, usize> {
    let mut result = execution_resources.builtin_instance_counter.clone();
    result.insert(
        String::from("n_steps"),
        execution_resources.n_steps + execution_resources.n_memory_holes,
    );
    result
}

type ResourcesMap = HashMap<String, usize>;

// TODO(Arni, 24/01/2024): Add state_diff_size to tx_weights
pub fn calculate_tx_weights(
    additional_os_resources: VmExecutionResources,
    actual_resources: ResourcesMap,
    message_segment_length: usize,
) -> Result<ResourcesMap, TransactionExecutionError> {
    let mut tx_weights: HashMap<String, usize> = HashMap::new();
    let mut cairo_resource_usage: HashMap<String, usize> = actual_resources;
    let value = cairo_resource_usage.remove("l1_gas_usage").ok_or(
        TransactionExecutionError::InvalidTransactionExecutionInfo {
            field: "l1_gas_usage".to_string(),
        },
    )?;
    tx_weights.insert("gas_weight".to_string(), value);
    let os_cairo_usage: HashMap<String, usize> =
        vm_execution_resources_to_hash_map(additional_os_resources);
    let cairo_usage = merge_hashmaps(&cairo_resource_usage, &os_cairo_usage);
    tx_weights.extend(cairo_usage);
    tx_weights.insert("message_segment_length".to_string(), message_segment_length);
    Ok(tx_weights)
}
