use std::collections::HashMap;

use crate::abi::constants;
use crate::context::{BlockContext, TransactionContext};
use crate::execution::call_info::{CallInfo, MessageL1CostInfo};
use crate::fee::eth_gas_constants;
use crate::fee::fee_utils::calculate_tx_gas_vector;
use crate::state::cached_state::StateChangesCount;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::objects::{
    GasVector, HasRelatedFeeType, ResourcesMapping, TransactionExecutionResult,
    TransactionPreValidationResult,
};
use crate::utils::{u128_from_usize, usize_from_u128};
use crate::versioned_constants::VersionedConstants;

#[cfg(test)]
#[path = "gas_usage_test.rs"]
pub mod test;

/// Returns an estimation of the L1 gas amount that will be used (by Starknet's state update and
/// the Verifier) following the addition of a transaction with the given parameters to a batch;
/// e.g., a message from L2 to L1 is followed by a storage write operation in Starknet L1 contract
/// which requires gas.
pub fn calculate_tx_gas_usage_vector<'a>(
    versioned_constants: &VersionedConstants,
    call_infos: impl Iterator<Item = &'a CallInfo>,
    state_changes_count: StateChangesCount,
    calldata_length: usize,
    l1_handler_payload_size: Option<usize>,
    use_kzg_da: bool,
) -> TransactionExecutionResult<GasVector> {
    Ok(calculate_messages_gas_vector(call_infos, l1_handler_payload_size)?
        + get_da_gas_cost(state_changes_count, use_kzg_da)
        + get_calldata_gas_cost(calldata_length, versioned_constants))
}

/// Returns an estimation of the gas usage for processing L1<>L2 messages on L1. Accounts for both
/// Starknet and SHARP contracts.
pub fn calculate_messages_gas_vector<'a>(
    call_infos: impl Iterator<Item = &'a CallInfo>,
    l1_handler_payload_size: Option<usize>,
) -> TransactionExecutionResult<GasVector> {
    let MessageL1CostInfo { l2_to_l1_payload_lengths, message_segment_length } =
        MessageL1CostInfo::calculate(call_infos, l1_handler_payload_size)?;

    let n_l2_to_l1_messages = l2_to_l1_payload_lengths.len();
    let n_l1_to_l2_messages = usize::from(l1_handler_payload_size.is_some());

    let starknet_gas_usage = GasVector {
        // Starknet's updateState gets the message segment as an argument.
        l1_gas: u128_from_usize(
            message_segment_length * eth_gas_constants::GAS_PER_MEMORY_WORD
            // Starknet's updateState increases a (storage) counter for each L2-to-L1 message.
            + n_l2_to_l1_messages * eth_gas_constants::GAS_PER_ZERO_TO_NONZERO_STORAGE_SET
            // Starknet's updateState decreases a (storage) counter for each L1-to-L2 consumed
            // message (note that we will probably get a refund of 15,000 gas for each consumed
            // message but we ignore it since refunded gas cannot be used for the current
            // transaction execution).
            + n_l1_to_l2_messages * eth_gas_constants::GAS_PER_COUNTER_DECREASE,
        )
        .expect("Could not convert starknet gas usage from usize to u128."),
        l1_data_gas: 0,
    } + get_consumed_message_to_l2_emissions_cost(l1_handler_payload_size)
        + get_log_message_to_l1_emissions_cost(&l2_to_l1_payload_lengths);

    let sharp_gas_usage = GasVector {
        l1_gas: u128_from_usize(
            message_segment_length * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD,
        )
        .expect("Could not convert sharp gas usage from usize to u128."),
        l1_data_gas: 0,
    };

    Ok(starknet_gas_usage + sharp_gas_usage)
}

// Return the gas cost for transaction calldata. Each calldata felt costs a fixed and configurable
// amount of gas. This cost represents the cost of storing the calldata on L2.
pub fn get_calldata_gas_cost(
    calldata_length: usize,
    versioned_constants: &VersionedConstants,
) -> GasVector {
    // TODO(Avi, 28/2/2024): Use rational numbers to calculate the gas cost once implemented.
    // TODO(Avi, 20/2/2024): Calculate the number of bytes instead of the number of felts.
    let milli_gas_per_calldata_word =
        versioned_constants.milli_gas_per_calldata_byte * eth_gas_constants::WORD_WIDTH;
    let calldata_gas_cost = calldata_length * milli_gas_per_calldata_word / 1000;
    GasVector {
        l1_gas: u128_from_usize(calldata_gas_cost)
            .expect("Could not convert calldata gas cost from usize to u128."),
        l1_data_gas: 0,
    }
}

/// Returns the number of felts added to the output data availability segment as a result of adding
/// a transaction to a batch. Note that constant cells - such as the one that holds the number of
/// modified contracts - are not counted.
pub fn get_onchain_data_segment_length(state_changes_count: StateChangesCount) -> usize {
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

/// Returns the gas cost of data availability on L1.
pub fn get_da_gas_cost(state_changes_count: StateChangesCount, use_kzg_da: bool) -> GasVector {
    let onchain_data_segment_length = get_onchain_data_segment_length(state_changes_count);

    let (l1_gas, blob_gas) = if use_kzg_da {
        (
            0,
            u128_from_usize(
                onchain_data_segment_length * eth_gas_constants::DATA_GAS_PER_FIELD_ELEMENT,
            )
            .expect("Failed to convert blob gas usage from usize to u128."),
        )
    } else {
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

        let gas = if naive_cost < discount {
            // Cost must be non-negative after discount.
            0
        } else {
            naive_cost - discount
        };

        (u128_from_usize(gas).expect("Failed to convert L1 gas usage from usize to u128."), 0)
    };

    GasVector { l1_gas, l1_data_gas: blob_gas }
}

/// Returns the number of felts added to the output messages segment as a result of adding
/// a transaction with the given parameters to a batch. Note that constant cells - such as the one
/// that holds the segment size - are not counted.
pub fn get_message_segment_length(
    l2_to_l1_payload_lengths: &[usize],
    l1_handler_payload_size: Option<usize>,
) -> usize {
    // Add L2-to-L1 message segment length; for each message, the OS outputs the following:
    // to_address, from_address, payload_size, payload.
    let mut message_segment_length = l2_to_l1_payload_lengths
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
pub fn get_consumed_message_to_l2_emissions_cost(
    l1_handler_payload_size: Option<usize>,
) -> GasVector {
    match l1_handler_payload_size {
        // The corresponding transaction is not an L1 handler.,
        None => GasVector { l1_gas: 0, l1_data_gas: 0 },
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
pub fn get_log_message_to_l1_emissions_cost(l2_to_l1_payload_lengths: &[usize]) -> GasVector {
    l2_to_l1_payload_lengths
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

fn get_event_emission_cost(n_topics: usize, data_length: usize) -> GasVector {
    GasVector {
        l1_gas: u128_from_usize(
            eth_gas_constants::GAS_PER_LOG
                + (n_topics + constants::N_DEFAULT_TOPICS) * eth_gas_constants::GAS_PER_LOG_TOPIC
                + data_length * eth_gas_constants::GAS_PER_LOG_DATA_WORD,
        )
        .expect("Cannot convert event emission gas from usize to u128."),
        l1_data_gas: 0,
    }
}

/// Return an estimated lower bound for the L1 gas on an account transaction.
pub fn estimate_minimal_gas_vector(
    block_context: &BlockContext,
    tx: &AccountTransaction,
) -> TransactionPreValidationResult<GasVector> {
    // TODO(Dori, 1/8/2023): Give names to the constant VM step estimates and regression-test them.
    let BlockContext { block_info, versioned_constants, .. } = block_context;
    let os_steps_for_type =
        versioned_constants.os_resources_for_tx_type(&tx.tx_type(), tx.calldata_length()).n_steps;
    let state_changes_by_account_transaction = match tx {
        // We consider the following state changes: sender balance update (storage update) + nonce
        // increment (contract modification) (we exclude the sequencer balance update and the ERC20
        // contract modification since it occurs for every tx).
        AccountTransaction::Declare(_) => StateChangesCount {
            n_storage_updates: 1,
            n_class_hash_updates: 0,
            n_compiled_class_hash_updates: 0,
            n_modified_contracts: 1,
        },
        AccountTransaction::Invoke(_) => StateChangesCount {
            n_storage_updates: 1,
            n_class_hash_updates: 0,
            n_compiled_class_hash_updates: 0,
            n_modified_contracts: 1,
        },
        // DeployAccount also updates the address -> class hash mapping.
        AccountTransaction::DeployAccount(_) => StateChangesCount {
            n_storage_updates: 1,
            n_class_hash_updates: 1,
            n_compiled_class_hash_updates: 0,
            n_modified_contracts: 1,
        },
    };
    let GasVector { l1_gas: gas_cost, l1_data_gas: blob_gas_cost } =
        get_da_gas_cost(state_changes_by_account_transaction, block_info.use_kzg_da);

    let resources = ResourcesMapping(HashMap::from([
        (
            constants::L1_GAS_USAGE.to_string(),
            usize_from_u128(gas_cost).expect("Failed to convert L1 gas cost from u128 to usize."),
        ),
        (
            constants::BLOB_GAS_USAGE.to_string(),
            usize_from_u128(blob_gas_cost)
                .expect("Failed to convert L1 blob gas cost from u128 to usize."),
        ),
        (constants::N_STEPS_RESOURCE.to_string(), os_steps_for_type),
    ]));

    Ok(calculate_tx_gas_vector(&resources, versioned_constants)?)
}

/// Compute l1_gas estimation from gas_vector using the following formula:
/// One byte of data costs either 1 data gas (in blob mode) or 16 gas (in calldata
/// mode). For gas price GP and data gas price DGP, the discount for using blobs
/// would be DGP / (16 * GP).
/// X non-data-related gas consumption and Y bytes of data, in non-blob mode, would
/// cost (X + 16*Y) units of gas. Applying the discount ratio to the data-related
/// summand, we get total_gas = (X + Y * DGP / GP).
pub fn compute_discounted_gas_from_gas_vector(
    gas_usage_vector: &GasVector,
    tx_context: &TransactionContext,
) -> u128 {
    let gas_prices = &tx_context.block_context.block_info.gas_prices;
    let GasVector { l1_gas: gas_usage, l1_data_gas: blob_gas_usage } = gas_usage_vector;
    let fee_type = tx_context.tx_info.fee_type();
    let gas_price = gas_prices.get_gas_price_by_fee_type(&fee_type);
    let data_gas_price = gas_prices.get_data_gas_price_by_fee_type(&fee_type);
    gas_usage + (blob_gas_usage * u128::from(data_gas_price)) / gas_price
}
