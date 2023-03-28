use crate::abi::constants;
use crate::execution::entry_point::MessageToL1;

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

/// Returns the number of felts added to the output messages segment as a result of adding a
/// transaction with the given parameters to a batch. Note that constant cells - such as the one
/// that holds the segment size - are not counted.
pub fn get_message_segment_length(
    l2_to_l1_messages: Vec<MessageToL1>,
    l1_handler_payload_size: Option<u64>,
) -> u64 {
    let message_segment_length: u64 = l2_to_l1_messages
        .iter()
        .map(|message| (message.payload.0.len() as u64) + constants::L2_TO_L1_MSG_HEADER_SIZE)
        .sum();

    match l1_handler_payload_size {
        None => message_segment_length,
        Some(size) => message_segment_length + constants::L1_TO_L2_MSG_HEADER_SIZE + size,
    }
}
