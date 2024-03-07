use std::collections::HashMap;

use cairo_vm::vm::runners::builtin_runner::SEGMENT_ARENA_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use starknet_api::transaction::TransactionVersion;

use crate::abi::constants;
use crate::execution::call_info::CallInfo;
use crate::execution::contract_class::ContractClass;
use crate::fee::gas_usage::get_onchain_data_segment_length;
use crate::state::cached_state::StateChangesCount;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{GasVector, ResourcesMapping, TransactionExecutionResult};
use crate::transaction::transaction_types::TransactionType;
use crate::utils::usize_from_u128;
use crate::versioned_constants::VersionedConstants;

/// Calculates the total resources needed to include the transaction in a Starknet block as
/// most-recent (recent w.r.t. application on the given state).
/// I.e., Cairo VM execution resources.
pub fn calculate_tx_resources(
    versioned_constants: &VersionedConstants,
    execution_resources: &ExecutionResources,
    gas_vector: GasVector,
    tx_type: TransactionType,
    calldata_length: usize,
    state_changes_count: StateChangesCount,
    use_kzg_da: bool,
) -> TransactionExecutionResult<ResourcesMapping> {
    let l1_gas_usage = usize_from_u128(gas_vector.l1_gas)
        .expect("This conversion should not fail as the value is a converted usize.");
    let l1_blob_gas_usage = usize_from_u128(gas_vector.l1_data_gas)
        .expect("This conversion should not fail as the value is a converted usize.");
    // Add additional Cairo resources needed for the OS to run the transaction.
    let data_segment_length = get_onchain_data_segment_length(state_changes_count);
    let total_vm_usage = execution_resources
        + &versioned_constants.get_additional_os_tx_resources(
            tx_type,
            calldata_length,
            data_segment_length,
            use_kzg_da,
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
    contract_class: &ContractClass,
    declare_version: TransactionVersion,
) -> Result<(), TransactionExecutionError> {
    match contract_class {
        ContractClass::V0(_) => {
            if let TransactionVersion::ZERO | TransactionVersion::ONE = declare_version {
                return Ok(());
            }
            Err(TransactionExecutionError::ContractClassVersionMismatch {
                declare_version,
                cairo_version: 0,
            })
        }
        ContractClass::V1(_) => {
            if let TransactionVersion::TWO | TransactionVersion::THREE = declare_version {
                return Ok(());
            }
            Err(TransactionExecutionError::ContractClassVersionMismatch {
                declare_version,
                cairo_version: 1,
            })
        }
        ContractClass::V1Sierra(_) => todo!("Sierra verify contract class version"),
    }
}
