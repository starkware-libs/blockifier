use std::collections::HashMap;

use cairo_vm::vm::runners::builtin_runner::SEGMENT_ARENA_BUILTIN_NAME;

use crate::abi::constants;
use crate::execution::call_info::CallInfo;
use crate::execution::entry_point::ExecutionResources;
use crate::fee::gas_usage::calculate_tx_gas_usage;
use crate::fee::os_usage::get_additional_os_resources;
use crate::state::cached_state::StateChangesCount;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionResult};
use crate::transaction::transaction_types::TransactionType;

pub fn verify_no_calls_to_other_contracts(
    call_info: &CallInfo,
    entry_point_kind: String,
) -> TransactionExecutionResult<()> {
    let invoked_contract_address = call_info.call.storage_address;
    if call_info
        .into_iter()
        .any(|inner_call| inner_call.call.storage_address != invoked_contract_address)
    {
        return Err(TransactionExecutionError::UnauthorizedInnerCall { entry_point_kind });
    }

    Ok(())
}

pub fn calculate_l1_gas_usage(
    call_infos: &[&CallInfo],
    state_changes_count: StateChangesCount,
    l1_handler_payload_size: Option<usize>,
) -> TransactionExecutionResult<usize> {
    let mut l2_to_l1_payloads_length = vec![];
    for call_info in call_infos {
        l2_to_l1_payloads_length.extend(call_info.get_sorted_l2_to_l1_payloads_length()?);
    }

    let l1_gas_usage = calculate_tx_gas_usage(
        &l2_to_l1_payloads_length,
        state_changes_count,
        l1_handler_payload_size,
    );

    Ok(l1_gas_usage)
}

/// Calculates the total resources needed to include the transaction in a StarkNet block as
/// most-recent (recent w.r.t. application on the given state).
/// I.e., Cairo VM execution resources.
pub fn calculate_tx_resources(
    execution_resources: &ExecutionResources,
    l1_gas_usage: usize,
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
        (constants::GAS_USAGE.to_string(), l1_gas_usage),
        (constants::N_STEPS_RESOURCE.to_string(), n_steps + total_vm_usage.n_memory_holes),
    ]);
    tx_resources.extend(total_vm_usage.builtin_instance_counter);

    Ok(ResourcesMapping(tx_resources))
}

pub fn update_remaining_gas(remaining_gas: &mut u64, call_info: &CallInfo) {
    *remaining_gas -= call_info.execution.gas_consumed;
}
