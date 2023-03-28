use super::eth_gas_constants;
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

fn get_event_emission_cost(n_topics: u64, data_length: u64) -> u64 {
    eth_gas_constants::GAS_PER_LOG
        + (n_topics + constants::N_DEFAULT_TOPICS) * eth_gas_constants::GAS_PER_LOG_TOPIC
        + data_length * eth_gas_constants::GAS_PER_LOG_DATA_WORD
}
