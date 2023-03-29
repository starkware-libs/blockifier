use crate::abi::constants;

/// Returns the number of felts added to the output data availability segment as a result of adding
/// a transaction to a batch. Note that constant cells - such as the one that holds the number of
/// modified contracts - are not counted.
/// This segment consists of deployment info (of contracts deployed by the transaction) and
/// storage updates.
pub fn get_onchain_data_segment_length(
    n_modified_contracts: u64,
    n_storage_changes: u64,
    n_class_updates: u64,
) -> u64 {
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
    payload_lengths: &[usize],
    l1_handler_payload_size: Option<usize>,
) -> usize {
    // Add L2-to-L1 message segment length; for each message, the OS outputs the following:
    // to_address, from_address, payload_size, payload.
    let mut message_segment_length = payload_lengths
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
