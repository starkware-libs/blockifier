use crate::abi::constants;
use crate::fee::eth_gas_constants;

/// Returns an estimation of the L1 gas amount that will be used (by StarkNet's update state and
/// the verifier) following the addition of a transaction with the given parameters to a batch;
/// e.g., a message from L2 to L1 is followed by a storage write operation in StarkNet L1 contract
/// which requires gas.
pub fn calculate_tx_gas_usage(
    l2_to_l1_payloads_length: &[usize],
    n_modified_contracts: usize,
    n_storage_changes: usize,
    l1_handler_payload_size: Option<usize>,
    n_class_updates: usize,
) -> usize {
    // Calculate the addition of the transaction to the output messages segment.
    let residual_message_segment_length =
        get_message_segment_length(l2_to_l1_payloads_length, l1_handler_payload_size);

    // Calculate the effect of the transaction on the output data availability segment.
    let residual_onchain_data_segment_length =
        get_onchain_data_segment_length(n_modified_contracts, n_storage_changes, n_class_updates);

    let n_l2_to_l1_messages = l2_to_l1_payloads_length.len();
    let n_l1_to_l2_messages = if l1_handler_payload_size.is_some() { 1 } else { 0 };

    let starknet_gas_usage =
    // StarkNet's updateState gets the message segment as an argument.
    residual_message_segment_length * eth_gas_constants::GAS_PER_MEMORY_WORD
    // StarkNet's updateState increases a (storage) counter for each L2-to-L1 message.
    + n_l2_to_l1_messages * eth_gas_constants::GAS_PER_ZERO_TO_NONZERO_STORAGE_SET
    // StarkNet's updateState decreases a (storage) counter for each L1-to-L2 consumed message.
    // (Note that we will probably get a refund of 15,000 gas for each consumed message but we 
    // ignore it since refunded gas cannot be used for the current transaction execution).
    + n_l1_to_l2_messages * eth_gas_constants::GAS_PER_COUNTER_DECREASE
    + get_consumed_message_to_l2_emissions_cost(l1_handler_payload_size)
    + get_log_message_to_l1_emissions_cost(l2_to_l1_payloads_length);

    let sharp_gas_usage = residual_message_segment_length
        * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD
        + residual_onchain_data_segment_length * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD;

    starknet_gas_usage + sharp_gas_usage
}

/// Returns the number of felts added to the output data availability segment as a result of adding
/// a transaction to a batch. Note that constant cells - such as the one that holds the number of
/// modified contracts - are not counted.
/// This segment consists of deployment info (of contracts deployed by the transaction) and
/// storage updates.
pub fn get_onchain_data_segment_length(
    n_modified_contracts: usize,
    n_storage_changes: usize,
    n_class_updates: usize,
) -> usize {
    // For each newly modified contract: contract address, number of modified storage cells.
    let mut onchain_data_segment_length = n_modified_contracts * 2;
    // For each class updated (through a deploy or a class replacement).
    onchain_data_segment_length += n_class_updates * constants::CLASS_UPDATE_SIZE;
    // For each modified storage cell: key, new value.
    onchain_data_segment_length += n_storage_changes * 2;

    onchain_data_segment_length
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
