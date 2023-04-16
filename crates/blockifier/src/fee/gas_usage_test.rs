use crate::fee::eth_gas_constants;
use crate::fee::gas_usage::{
    calculate_tx_gas_usage, get_consumed_message_to_l2_emissions_cost,
    get_log_message_to_l1_emissions_cost, get_message_segment_length,
    get_onchain_data_segment_length,
};

/// This test goes over five cases. In each case, we calculate the gas usage given the parameters.
/// We then perform the same calculation manually, each time using only the relevant parameters.
/// The five cases are:
///     1. A DeployAccount transaction.
///     2. An L1 handler.
///     3. A transaction with L2-to-L1 messages.
///     4. A transaction that modifies the storage.
///     5. A combination of cases 2. 3. and 4.
#[test]
fn test_calculate_tx_gas_usage_basic() {
    // DeployAccount.

    let deploy_account_n_class_updates = 1;
    let deploy_account_gas_usage =
        calculate_tx_gas_usage(&[], 0, 0, None, deploy_account_n_class_updates);

    // Manual calculation.
    let manual_starknet_gas_usage = 0;
    let onchain_data_segment_length =
        get_onchain_data_segment_length(0, 0, deploy_account_n_class_updates);
    let manual_sharp_gas_usage =
        onchain_data_segment_length * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD;

    assert_eq!(deploy_account_gas_usage, manual_starknet_gas_usage + manual_sharp_gas_usage);

    // L1 handler.

    let l1_handler_payload_size = 4;
    let l1_handler_gas_usage = calculate_tx_gas_usage(&[], 0, 0, Some(l1_handler_payload_size), 0);

    // Manual calculation.
    let message_segment_length = get_message_segment_length(&[], Some(l1_handler_payload_size));
    let manual_starknet_gas_usage = message_segment_length * eth_gas_constants::GAS_PER_MEMORY_WORD
        + eth_gas_constants::GAS_PER_COUNTER_DECREASE
        + get_consumed_message_to_l2_emissions_cost(Some(l1_handler_payload_size));
    let manual_sharp_gas_usage =
        message_segment_length * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD;

    assert_eq!(l1_handler_gas_usage, manual_starknet_gas_usage + manual_sharp_gas_usage);

    // Any transaction with L2-to-L1 messages.

    let l2_to_l1_payloads_length: [usize; 4] = [0, 1, 2, 3];
    let l2_to_l1_messages_gas_usage =
        calculate_tx_gas_usage(&l2_to_l1_payloads_length, 0, 0, None, 0);

    // Manual calculation.
    let message_segment_length = get_message_segment_length(&l2_to_l1_payloads_length, None);
    let n_l2_to_l1_messages = l2_to_l1_payloads_length.len();
    let manual_starknet_gas_usage = message_segment_length * eth_gas_constants::GAS_PER_MEMORY_WORD
        + n_l2_to_l1_messages * eth_gas_constants::GAS_PER_ZERO_TO_NONZERO_STORAGE_SET
        + get_log_message_to_l1_emissions_cost(&l2_to_l1_payloads_length);
    let manual_sharp_gas_usage =
        message_segment_length * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD;

    assert_eq!(l2_to_l1_messages_gas_usage, manual_starknet_gas_usage + manual_sharp_gas_usage);

    // Any calculation with storage writings.

    let n_modified_contracts = 7;
    let n_storage_changes = 11;
    let storage_writings_gas_usage =
        calculate_tx_gas_usage(&[], n_modified_contracts, n_storage_changes, None, 0);

    // Manual calculation.
    let manual_starknet_gas_usage = 0;
    let onchain_data_segment_length =
        get_onchain_data_segment_length(n_modified_contracts, n_storage_changes, 0);
    let manual_sharp_gas_usage =
        onchain_data_segment_length * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD;

    assert_eq!(storage_writings_gas_usage, manual_starknet_gas_usage + manual_sharp_gas_usage);

    // Combined case of an L1 handler.

    let gas_usage = calculate_tx_gas_usage(
        &l2_to_l1_payloads_length,
        n_modified_contracts,
        n_storage_changes,
        Some(l1_handler_payload_size),
        0,
    );

    // Manual calculation.
    let expected_gas_usage =
        l1_handler_gas_usage + l2_to_l1_messages_gas_usage + storage_writings_gas_usage;

    assert_eq!(gas_usage, expected_gas_usage);
}
