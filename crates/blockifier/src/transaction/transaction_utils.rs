use std::collections::HashMap;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use starknet_api::transaction::Fee;

use crate::abi::constants;
use crate::block_context::BlockContext;
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

pub fn calculate_tx_fee(_block_context: &BlockContext) -> Fee {
    Fee(2)
}

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
    resources_manager: ExecutionResources,
    validate_call_info: Option<&CallInfo>,
    execute_call_info: Option<&CallInfo>,
    tx_type: TransactionType,
    state: &mut TransactionalState<'_, S>,
    l1_handler_payload_size: Option<usize>,
) -> TransactionExecutionResult<ResourcesMapping> {
    let (n_storage_changes, n_modified_contracts, n_class_updates) =
        state.count_actual_state_changes();

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
    );

    // TODO(Noa, 30/04/23): Consider adding builtin suffix in the VM or remove the suffix from the
    // flow.
    let mut builtin_instance_counter: HashMap<String, usize> = HashMap::new();
    for (name, value) in resources_manager.vm_resources.builtin_instance_counter {
        builtin_instance_counter.insert(name + BUILTIN_NAME_SUFFIX, value);
    }
    let cairo_usage =
        VmExecutionResources { builtin_instance_counter, ..resources_manager.vm_resources };

    // Add additional Cairo resources needed for the OS to run the transaction.
    let total_cairo_usage =
        &cairo_usage + &get_additional_os_resources(resources_manager.syscall_counter, tx_type)?;
    let total_cairo_usage = total_cairo_usage.filter_unused_builtins();
    let mut tx_resources = HashMap::from([
        (constants::GAS_USAGE.to_string(), l1_gas_usage),
        (
            constants::N_STEPS_RESOURCE.to_string(),
            total_cairo_usage.n_steps + total_cairo_usage.n_memory_holes,
        ),
    ]);
    tx_resources.extend(total_cairo_usage.builtin_instance_counter);

    Ok(ResourcesMapping(tx_resources))
}
