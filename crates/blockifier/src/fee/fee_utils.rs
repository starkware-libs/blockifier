use std::collections::HashMap;

use super::gas_usage::calculate_tx_gas_usage;
use super::os_usage::get_additional_os_resources;
use crate::execution::entry_point::{CallInfo, ExecutionResources};
use crate::state::cached_state::TransactionalState;
use crate::state::state_api::StateReader;
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionResult};
use crate::transaction::transaction_types::TransactionType;

const FEE_TRANSFER_N_STORAGE_CHANGES: u32 = 2; // Sender and sequencer balance update.
// Exclude the sequencer balance update, since it's charged once throughout the batch.
const FEE_TRANSFER_N_STORAGE_CHANGES_TO_CHARGE: u32 = FEE_TRANSFER_N_STORAGE_CHANGES - 1;

/// Returns the total resources needed to include the most recent transaction in a StarkNet batch
/// (recent w.r.t. application on the given state) i.e., L1 gas usage and Cairo execution resources.
/// Used for transaction fee; calculation is made as if the transaction is the first in batch, for
/// consistency.
pub fn calculate_tx_resources<S: StateReader>(
    resources_manager: ExecutionResources,
    call_infos: &[Option<CallInfo>],
    tx_type: TransactionType,
    state: &mut TransactionalState<'_, S>,
    l1_handler_payload_size: Option<usize>,
) -> TransactionExecutionResult<ResourcesMapping> {
    let (n_storage_changes, n_modified_contracts, n_class_updates) =
        state.count_actual_state_changes();

    let non_optional_call_infos: Vec<&CallInfo> = call_infos.iter().flatten().collect();
    let mut l2_to_l1_payloads_length = vec![];
    for call_info in non_optional_call_infos {
        l2_to_l1_payloads_length.extend(call_info.get_sorted_l2_to_l1_payloads_length()?);
    }

    let l1_gas_usage = calculate_tx_gas_usage(
        &l2_to_l1_payloads_length,
        n_modified_contracts,
        n_storage_changes + FEE_TRANSFER_N_STORAGE_CHANGES_TO_CHARGE as usize,
        l1_handler_payload_size,
        n_class_updates,
    );

    let mut cairo_usage = resources_manager.vm_resources;
    // Add additional Cairo resources needed for the OS to run the transaction.
    cairo_usage += &get_additional_os_resources(resources_manager.syscall_counter, tx_type)?;
    cairo_usage = cairo_usage.filter_unused_builtins();
    let mut tx_resources = HashMap::from([
        ("l1_gas_usage".to_string(), l1_gas_usage),
        ("n_steps".to_string(), cairo_usage.n_steps + cairo_usage.n_memory_holes),
    ]);
    tx_resources.clone_from(&cairo_usage.builtin_instance_counter);

    Ok(ResourcesMapping(tx_resources))
}

pub fn extract_l1_gas_and_cairo_usage(
    resources: &ResourcesMapping,
) -> (usize, HashMap<String, usize>) {
    let mut cairo_resource_usage = resources.0.clone();
    let l1_gas_usage = cairo_resource_usage
        .remove("l1_gas_usage")
        .expect("`ResourcesMapping` does not have the key `l1_gas_usage`.");

    (l1_gas_usage, cairo_resource_usage)
}
