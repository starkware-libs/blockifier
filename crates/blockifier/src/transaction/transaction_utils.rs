use std::collections::HashMap;

use crate::abi::constants;
use crate::execution::entry_point::{CallInfo, ExecutionResources};
use crate::fee::gas_usage::calculate_tx_gas_usage;
use crate::fee::os_usage::get_additional_os_resources;
use crate::state::cached_state::TransactionalState;
use crate::state::state_api::StateReader;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionResult};
use crate::transaction::transaction_types::TransactionType;

pub const BUILTIN_NAME_SUFFIX: &str = "_builtin";

const FEE_TRANSFER_N_STORAGE_CHANGES: u8 = 2; // Sender and sequencer balance update.
// Exclude the sequencer balance update, since it's charged once throughout the batch.
const FEE_TRANSFER_N_STORAGE_CHANGES_TO_CHARGE: u8 = FEE_TRANSFER_N_STORAGE_CHANGES - 1;

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

/// Calculates the total resources needed to include the transaction in a StarkNet block as
/// most-recent (recent w.r.t. application on the given state).
/// I.e., L1 gas usage and Cairo VM execution resources.
pub fn calculate_tx_resources<S: StateReader>(
    execution_resources: ExecutionResources,
    validate_call_info: Option<&CallInfo>,
    execute_call_info: Option<&CallInfo>,
    tx_type: TransactionType,
    state: &mut TransactionalState<'_, S>,
    l1_handler_payload_size: Option<usize>,
    is_0_10: bool,
) -> TransactionExecutionResult<ResourcesMapping> {
    let (n_storage_changes, n_modified_contracts, n_class_updates) =
        state.count_actual_state_changes(is_0_10);

    let non_optional_call_infos: Vec<&CallInfo> = vec![execute_call_info, validate_call_info]
        .iter()
        .flat_map(|&optional_call_info| optional_call_info)
        .collect();

    let mut l2_to_l1_payloads_length = vec![];
    for call_info in non_optional_call_infos {
        l2_to_l1_payloads_length.extend(call_info.get_sorted_l2_to_l1_payloads_length()?);
    }

    let l1_gas_usage = calculate_tx_gas_usage(
        &l2_to_l1_payloads_length,
        n_modified_contracts,
        n_storage_changes + usize::from(FEE_TRANSFER_N_STORAGE_CHANGES_TO_CHARGE),
        l1_handler_payload_size,
        n_class_updates,
        is_0_10,
    );

    // Add additional Cairo resources needed for the OS to run the transaction.
    let total_vm_usage = &execution_resources.vm_resources
        + &get_additional_os_resources(execution_resources.syscall_counter, tx_type, is_0_10)?;
    let total_vm_usage = total_vm_usage.filter_unused_builtins();
    let mut tx_resources = HashMap::from([
        (constants::GAS_USAGE.to_string(), l1_gas_usage),
        (
            constants::N_STEPS_RESOURCE.to_string(),
            total_vm_usage.n_steps + total_vm_usage.n_memory_holes,
        ),
    ]);
    tx_resources.extend(total_vm_usage.builtin_instance_counter);

    Ok(ResourcesMapping(tx_resources))
}
