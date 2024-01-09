use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::L2ToL1Payload;

use crate::execution::call_info::{CallExecution, CallInfo, MessageToL1, OrderedL2ToL1Message};
use crate::fee::eth_gas_constants;
use crate::fee::gas_usage::{
    calculate_tx_gas_usage, get_consumed_message_to_l2_emissions_cost,
    get_log_message_to_l1_emissions_cost, get_message_segment_length, get_onchain_data_cost,
};
use crate::state::cached_state::StateChangesCount;

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

    let deploy_account_state_changes_count = StateChangesCount {
        n_storage_updates: 0,
        n_class_hash_updates: 1,
        n_compiled_class_hash_updates: 0,
        n_modified_contracts: 1,
    };
    let deploy_account_gas_usage =
        calculate_tx_gas_usage(std::iter::empty(), deploy_account_state_changes_count, None);

    // Manual calculation.
    let manual_starknet_gas_usage = 0;
    let manual_sharp_gas_usage = get_onchain_data_cost(deploy_account_state_changes_count);

    assert!(deploy_account_gas_usage.is_ok());
    assert_eq!(
        deploy_account_gas_usage.unwrap(),
        manual_starknet_gas_usage + manual_sharp_gas_usage
    );

    // L1 handler.

    let l1_handler_payload_size = 4;
    let l1_handler_gas_usage = calculate_tx_gas_usage(
        std::iter::empty(),
        StateChangesCount::default(),
        Some(l1_handler_payload_size),
    );

    // Manual calculation.
    let message_segment_length = get_message_segment_length(&[], Some(l1_handler_payload_size));
    let manual_starknet_gas_usage = message_segment_length * eth_gas_constants::GAS_PER_MEMORY_WORD
        + eth_gas_constants::GAS_PER_COUNTER_DECREASE
        + get_consumed_message_to_l2_emissions_cost(Some(l1_handler_payload_size));
    let manual_sharp_gas_usage =
        message_segment_length * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD;

    assert!(l1_handler_gas_usage.is_ok());
    assert_eq!(
        *l1_handler_gas_usage.as_ref().unwrap(),
        manual_starknet_gas_usage + manual_sharp_gas_usage
    );

    // Any transaction with L2-to-L1 messages.

    let call_infos = vec![
        CallInfo {
            execution: CallExecution {
                l2_to_l1_messages: vec![OrderedL2ToL1Message {
                    message: Default::default(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        },
        CallInfo {
            execution: CallExecution {
                l2_to_l1_messages: vec![OrderedL2ToL1Message {
                    message: MessageToL1 {
                        payload: L2ToL1Payload(vec![stark_felt!(0_u16)]),
                        ..Default::default()
                    },
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        },
        CallInfo {
            execution: CallExecution {
                l2_to_l1_messages: vec![OrderedL2ToL1Message {
                    message: MessageToL1 {
                        payload: L2ToL1Payload(vec![stark_felt!(0_u16), stark_felt!(0_u16)]),
                        ..Default::default()
                    },
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        },
        CallInfo {
            execution: CallExecution {
                l2_to_l1_messages: vec![OrderedL2ToL1Message {
                    message: MessageToL1 {
                        payload: L2ToL1Payload(vec![
                            stark_felt!(0_u16),
                            stark_felt!(0_u16),
                            stark_felt!(0_u16),
                        ]),
                        ..Default::default()
                    },
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        },
    ];

    // l2_to_l1_payloads_length is [0, 1, 2, 3]
    let l2_to_l1_payloads_length: Vec<usize> = call_infos
        .iter()
        .flat_map(|call_info| call_info.get_sorted_l2_to_l1_payloads_length().unwrap())
        .collect();

    let l2_to_l1_state_changes_count = StateChangesCount {
        n_storage_updates: 0,
        n_class_hash_updates: 0,
        n_compiled_class_hash_updates: 0,
        n_modified_contracts: 1,
    };
    let l2_to_l1_messages_gas_usage =
        calculate_tx_gas_usage(call_infos.iter(), l2_to_l1_state_changes_count, None);

    // Manual calculation.
    let message_segment_length = get_message_segment_length(&l2_to_l1_payloads_length, None);
    let n_l2_to_l1_messages = l2_to_l1_payloads_length.len();
    let manual_starknet_gas_usage = message_segment_length * eth_gas_constants::GAS_PER_MEMORY_WORD
        + n_l2_to_l1_messages * eth_gas_constants::GAS_PER_ZERO_TO_NONZERO_STORAGE_SET
        + get_log_message_to_l1_emissions_cost(&l2_to_l1_payloads_length);
    let manual_sharp_gas_usage = message_segment_length
        * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD
        + get_onchain_data_cost(l2_to_l1_state_changes_count);

    assert!(l2_to_l1_messages_gas_usage.is_ok());
    assert_eq!(
        *l2_to_l1_messages_gas_usage.as_ref().unwrap(),
        manual_starknet_gas_usage + manual_sharp_gas_usage
    );

    // Any calculation with storage writings.

    let n_modified_contracts = 7;
    let n_storage_updates = 11;
    let storage_writes_state_changes_count = StateChangesCount {
        n_storage_updates,
        n_class_hash_updates: 0,
        n_compiled_class_hash_updates: 0,
        n_modified_contracts,
    };
    let storage_writings_gas_usage =
        calculate_tx_gas_usage(std::iter::empty(), storage_writes_state_changes_count, None);

    // Manual calculation.
    let manual_starknet_gas_usage = 0;
    let manual_sharp_gas_usage = get_onchain_data_cost(storage_writes_state_changes_count);

    assert!(storage_writings_gas_usage.is_ok());
    assert_eq!(
        *storage_writings_gas_usage.as_ref().unwrap(),
        manual_starknet_gas_usage + manual_sharp_gas_usage
    );

    // Combined case of an L1 handler, L2-to-L1 messages and storage writes.
    let combined_state_changes_count = StateChangesCount {
        n_storage_updates: storage_writes_state_changes_count.n_storage_updates,
        n_class_hash_updates: 0,
        n_compiled_class_hash_updates: 0,
        n_modified_contracts: storage_writes_state_changes_count.n_modified_contracts
            + l2_to_l1_state_changes_count.n_modified_contracts,
    };
    let gas_usage = calculate_tx_gas_usage(
        call_infos.iter(),
        combined_state_changes_count,
        Some(l1_handler_payload_size),
    );

    assert!(gas_usage.is_ok());

    // Manual calculation.
    let fee_balance_discount =
        eth_gas_constants::GAS_PER_MEMORY_WORD - eth_gas_constants::get_calldata_word_cost(12);

    // l2_to_l1_messages_gas_usage and storage_writings_gas_usage got a discount each, while
    // the combined calculation got it once.
    let expected_gas_usage = l1_handler_gas_usage.and_then(|l1_handler_gas_usage_val| {
        l2_to_l1_messages_gas_usage.and_then(|l2_to_l1_messages_gas_usage_val| {
            storage_writings_gas_usage.map(|storage_writings_gas_usage_val| {
                l1_handler_gas_usage_val
                    + l2_to_l1_messages_gas_usage_val
                    + storage_writings_gas_usage_val
                    + fee_balance_discount
            })
        })
    });

    assert!(expected_gas_usage.is_ok());
    assert_eq!(gas_usage.unwrap(), expected_gas_usage.unwrap());
}

#[test]
fn test_onchain_data_discount() {
    // Check that there's no negative cost.
    assert_eq!(get_onchain_data_cost(StateChangesCount::default()), 0);

    // Check discount: modified_contract_felt and fee balance discount.
    let state_changes_count = StateChangesCount {
        // Fee balance update.
        n_storage_updates: 1,
        n_modified_contracts: 7,
        ..StateChangesCount::default()
    };

    let modified_contract_calldata_cost = 6 * eth_gas_constants::GAS_PER_MEMORY_BYTE
        + 26 * eth_gas_constants::GAS_PER_MEMORY_ZERO_BYTE;
    let modified_contract_cost = modified_contract_calldata_cost
        + eth_gas_constants::SHARP_ADDITIONAL_GAS_PER_MEMORY_WORD
        - eth_gas_constants::DISCOUNT_PER_DA_WORD;
    let contract_address_cost = eth_gas_constants::SHARP_GAS_PER_DA_WORD;

    let fee_balance_value_calldata_cost = 12 * eth_gas_constants::GAS_PER_MEMORY_BYTE
        + 20 * eth_gas_constants::GAS_PER_MEMORY_ZERO_BYTE;
    let fee_balance_value_cost = fee_balance_value_calldata_cost
        + eth_gas_constants::SHARP_ADDITIONAL_GAS_PER_MEMORY_WORD
        - eth_gas_constants::DISCOUNT_PER_DA_WORD;
    let fee_balance_key_cost = eth_gas_constants::SHARP_GAS_PER_DA_WORD;

    let expected_cost = state_changes_count.n_modified_contracts
        * (contract_address_cost + modified_contract_cost)
        + fee_balance_key_cost
        + fee_balance_value_cost;

    assert_eq!(get_onchain_data_cost(state_changes_count), expected_cost);

    // Test 10% discount.
    let state_changes_count =
        StateChangesCount { n_storage_updates: 27, ..StateChangesCount::default() };

    let cost_without_discount = (state_changes_count.n_storage_updates * 2) * (512 + 100);
    let actual_cost = get_onchain_data_cost(state_changes_count);
    let cost_ratio = (actual_cost as f64) / (cost_without_discount as f64);
    assert!(cost_ratio <= 0.9);
    assert!(cost_ratio >= 0.88);
}
