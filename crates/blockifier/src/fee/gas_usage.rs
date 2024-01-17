use std::collections::HashMap;

use starknet_api::transaction::Fee;

use super::fee_utils::{calculate_tx_l1_gas_usage, get_fee_by_l1_gas_usage};
use crate::abi::constants;
use crate::block_context::BlockContext;
use crate::execution::call_info::CallInfo;
use crate::fee::eth_gas_constants;
use crate::fee::os_resources::OS_RESOURCES;
use crate::state::cached_state::StateChangesCount;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::objects::{
    HasRelatedFeeType, ResourcesMapping, TransactionExecutionResult, TransactionPreValidationResult,
};

#[cfg(test)]
#[path = "gas_usage_test.rs"]
pub mod test;

// TODO(Ayelet, 10/1/2024): Use to calculate message segment length in transaction_executer's
// execute
fn calculate_l2_to_l1_payloads_length_and_message_segment_length<'a>(
    call_infos: impl Iterator<Item = &'a CallInfo>,
    l1_handler_payload_size: Option<usize>,
) -> TransactionExecutionResult<(Vec<usize>, usize)> {
    let mut l2_to_l1_payloads_length = Vec::new();
    for call_info in call_infos {
        l2_to_l1_payloads_length.extend(call_info.get_sorted_l2_to_l1_payloads_length()?);
    }

    let message_segment_length =
        get_message_segment_length(&l2_to_l1_payloads_length, l1_handler_payload_size);

    Ok((l2_to_l1_payloads_length, message_segment_length))
}

/// Returns an estimation of the L1 gas amount that will be used by Starknet's verifier following
/// the addition of a transaction with the given parameters to a batch, excluding the gas used for
/// Starknet's state update; e.g., a message from L2 to L1 is followed by a storage write operation
/// in Starknet L1 contract which requires gas.
pub fn calculate_tx_gas_usage<'a>(
    call_infos: impl Iterator<Item = &'a CallInfo>,
    l1_handler_payload_size: Option<usize>,
) -> TransactionExecutionResult<usize> {
    let (l2_to_l1_payloads_length, residual_message_segment_length) =
        calculate_l2_to_l1_payloads_length_and_message_segment_length(
            call_infos,
            l1_handler_payload_size,
        )?;

    let n_l2_to_l1_messages = l2_to_l1_payloads_length.len();
    let n_l1_to_l2_messages = usize::from(l1_handler_payload_size.is_some());

    let starknet_gas_usage =
    // Starknet's updateState gets the message segment as an argument.
    residual_message_segment_length * eth_gas_constants::GAS_PER_MEMORY_WORD
    // Starknet's updateState increases a (storage) counter for each L2-to-L1 message.
    + n_l2_to_l1_messages * eth_gas_constants::GAS_PER_ZERO_TO_NONZERO_STORAGE_SET
    // Starknet's updateState decreases a (storage) counter for each L1-to-L2 consumed message.
    // (Note that we will probably get a refund of 15,000 gas for each consumed message but we
    // ignore it since refunded gas cannot be used for the current transaction execution).
    + n_l1_to_l2_messages * eth_gas_constants::GAS_PER_COUNTER_DECREASE
    + get_consumed_message_to_l2_emissions_cost(l1_handler_payload_size)
    + get_log_message_to_l1_emissions_cost(&l2_to_l1_payloads_length);

    let sharp_gas_usage_without_data =
        residual_message_segment_length * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD;

    Ok(starknet_gas_usage + sharp_gas_usage_without_data)
}

/// Returns an estimation of the L1 gas amount that will be used by Starknet's state update, for the
/// output data avilability segment.
/// TODO(Arni, 21/1/2024): Refactor the function to work generically for both gas in the
/// use_kzg_da=False case and data_gas in the use_kzg_da=True case.
pub fn calculate_tx_data_gas_usage(
    state_changes_count: StateChangesCount,
) -> TransactionExecutionResult<usize> {
    Ok(get_onchain_data_cost(state_changes_count))
}

/// Returns the number of felts added to the output data availability segment as a result of adding
/// a transaction to a batch. Note that constant cells - such as the one that holds the number of
/// modified contracts - are not counted.
fn get_onchain_data_segment_length(state_changes_count: StateChangesCount) -> usize {
    // For each newly modified contract:
    // contract address (1 word).
    // + 1 word with the following info: A flag indicating whether the class hash was updated, the
    // number of entry updates, and the new nonce.
    let mut onchain_data_segment_length = state_changes_count.n_modified_contracts * 2;
    // For each class updated (through a deploy or a class replacement).
    onchain_data_segment_length +=
        state_changes_count.n_class_hash_updates * constants::CLASS_UPDATE_SIZE;
    // For each modified storage cell: key, new value.
    onchain_data_segment_length += state_changes_count.n_storage_updates * 2;
    // For each compiled class updated (through declare): class_hash, compiled_class_hash
    onchain_data_segment_length += state_changes_count.n_compiled_class_hash_updates * 2;

    onchain_data_segment_length
}

/// Returns the gas cost of publishing the onchain data on L1.
pub fn get_onchain_data_cost(state_changes_count: StateChangesCount) -> usize {
    let onchain_data_segment_length = get_onchain_data_segment_length(state_changes_count);
    // TODO(Yoni, 1/5/2024): count the exact amount of nonzero bytes for each DA entry.
    let naive_cost = onchain_data_segment_length * eth_gas_constants::SHARP_GAS_PER_DA_WORD;

    // For each modified contract, the expected non-zeros bytes in the second word are:
    // 1 bytes for class hash flag; 2 for number of storage updates (up to 64K);
    // 3 for nonce update (up to 16M).
    let modified_contract_cost = eth_gas_constants::get_calldata_word_cost(1 + 2 + 3);
    let modified_contract_discount =
        eth_gas_constants::GAS_PER_MEMORY_WORD - modified_contract_cost;
    let mut discount = state_changes_count.n_modified_contracts * modified_contract_discount;

    // Up to balance of 8*(10**10) ETH.
    let fee_balance_value_cost = eth_gas_constants::get_calldata_word_cost(12);
    discount += eth_gas_constants::GAS_PER_MEMORY_WORD - fee_balance_value_cost;

    if naive_cost < discount {
        // Cost must be non-negative after discount.
        0
    } else {
        naive_cost - discount
    }
}

/// Returns the number of felts added to the output messages segment as a result of adding
/// a transaction with the given parameters to a batch. Note that constant cells - such as the one
/// that holds the segment size - are not counted.
pub fn get_message_segment_length(
    l2_to_l1_payloads_length: &[usize],
    l1_handler_payload_size: Option<usize>,
) -> usize {
    // Add L2-to-L1 message segment length; for each message, the OS outputs the following:
    // to_address, from_address, payload_size, payload.
    let mut message_segment_length = l2_to_l1_payloads_length
        .iter()
        .map(|payload_length| constants::L2_TO_L1_MSG_HEADER_SIZE + payload_length)
        .sum();

    if let Some(payload_size) = l1_handler_payload_size {
        // The corresponding transaction is of type L1 handler; add the length of the L1-to-L2
        // message sent by the sequencer (that will be outputted by the OS), which is of the
        // following format: from_address=calldata[0], to_address=contract_address,
        // nonce, selector, payload_size, payload=calldata[1:].
        message_segment_length += constants::L1_TO_L2_MSG_HEADER_SIZE + payload_size;
    }

    message_segment_length
}

/// Returns the cost of ConsumedMessageToL2 event emissions caused by an L1 handler with the given
/// payload size.
pub fn get_consumed_message_to_l2_emissions_cost(l1_handler_payload_size: Option<usize>) -> usize {
    match l1_handler_payload_size {
        None => 0, // The corresponding transaction is not an L1 handler.,
        Some(l1_handler_payload_size) => {
            get_event_emission_cost(
                constants::CONSUMED_MSG_TO_L2_N_TOPICS,
                // We're assuming the existence of one (not indexed) payload array.
                constants::CONSUMED_MSG_TO_L2_ENCODED_DATA_SIZE + l1_handler_payload_size,
            )
        }
    }
}

/// Returns the cost of LogMessageToL1 event emissions caused by the given messages payload length.
pub fn get_log_message_to_l1_emissions_cost(l2_to_l1_payloads_length: &[usize]) -> usize {
    l2_to_l1_payloads_length
        .iter()
        .map(|length| {
            get_event_emission_cost(
                constants::LOG_MSG_TO_L1_N_TOPICS,
                // We're assuming the existence of one (not indexed) payload array.
                constants::LOG_MSG_TO_L1_ENCODED_DATA_SIZE + *length,
            )
        })
        .sum()
}

fn get_event_emission_cost(n_topics: usize, data_length: usize) -> usize {
    eth_gas_constants::GAS_PER_LOG
        + (n_topics + constants::N_DEFAULT_TOPICS) * eth_gas_constants::GAS_PER_LOG_TOPIC
        + data_length * eth_gas_constants::GAS_PER_LOG_DATA_WORD
}

/// Return an estimated lower bound for the L1 gas on an account transaction.
pub fn estimate_minimal_l1_gas(
    block_context: &BlockContext,
    tx: &AccountTransaction,
) -> TransactionPreValidationResult<u128> {
    // TODO(Dori, 1/8/2023): Give names to the constant VM step estimates and regression-test them.
    let os_steps_for_type = OS_RESOURCES.resources_for_tx_type(&tx.tx_type()).n_steps;
    let gas_cost: usize = match tx {
        // We consider the following state changes: sender balance update (storage update) + nonce
        // increment (contract modification) (we exclude the sequencer balance update and the ERC20
        // contract modification since it occurs for every tx).
        AccountTransaction::Declare(_) => get_onchain_data_cost(StateChangesCount {
            n_storage_updates: 1,
            n_class_hash_updates: 0,
            n_compiled_class_hash_updates: 0,
            n_modified_contracts: 1,
        }),
        AccountTransaction::Invoke(_) => get_onchain_data_cost(StateChangesCount {
            n_storage_updates: 1,
            n_class_hash_updates: 0,
            n_compiled_class_hash_updates: 0,
            n_modified_contracts: 1,
        }),
        // DeployAccount also updates the address -> class hash mapping.
        AccountTransaction::DeployAccount(_) => get_onchain_data_cost(StateChangesCount {
            n_storage_updates: 1,
            n_class_hash_updates: 1,
            n_compiled_class_hash_updates: 0,
            n_modified_contracts: 1,
        }),
    };
    let resources = ResourcesMapping(HashMap::from([
        (constants::GAS_USAGE.to_string(), gas_cost),
        (constants::N_STEPS_RESOURCE.to_string(), os_steps_for_type),
    ]));

    Ok(calculate_tx_l1_gas_usage(&resources, block_context)?)
}

pub fn estimate_minimal_fee(
    block_context: &BlockContext,
    tx: &AccountTransaction,
) -> TransactionExecutionResult<Fee> {
    let estimated_minimal_l1_gas = estimate_minimal_l1_gas(block_context, tx)?;
    Ok(get_fee_by_l1_gas_usage(block_context, estimated_minimal_l1_gas, &tx.fee_type()))
}
