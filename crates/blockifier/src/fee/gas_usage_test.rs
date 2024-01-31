use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::L2ToL1Payload;

use crate::execution::call_info::{CallExecution, CallInfo, MessageToL1, OrderedL2ToL1Message};
use crate::fee::eth_gas_constants;
use crate::fee::gas_usage::{
    calculate_tx_blob_gas_usage, calculate_tx_gas_usage_vector,
    get_consumed_message_to_l2_emissions_cost, get_log_message_to_l1_emissions_cost,
    get_message_segment_length, get_onchain_data_cost,
};
use crate::state::cached_state::StateChangesCount;
use crate::transaction::objects::GasVector;
use crate::utils::{u128_from_usize, usize_from_u128};

#[rstest]
#[case::storage_write(StateChangesCount {
    n_storage_updates: 1,
    n_class_hash_updates:0,
    n_compiled_class_hash_updates:0,
    n_modified_contracts:0,
})
]
#[case::deploy_account(StateChangesCount {
    n_storage_updates: 0,
    n_class_hash_updates:1,
    n_compiled_class_hash_updates:0,
    n_modified_contracts:1,
})
]
#[case::declare(StateChangesCount {
    n_storage_updates: 0,
    n_class_hash_updates:0,
    n_compiled_class_hash_updates:1,
    n_modified_contracts:0,
})
]
#[case::general_scenario(StateChangesCount {
    n_storage_updates: 7,
    n_class_hash_updates:11,
    n_compiled_class_hash_updates:13,
    n_modified_contracts:17,
})
]
fn test_calculate_tx_blob_gas_usage_basic(#[case] state_changes_count: StateChangesCount) {
    // Manual calculation.
    let on_chain_data_segment_length = state_changes_count.n_storage_updates * 2
        + state_changes_count.n_class_hash_updates
        + state_changes_count.n_compiled_class_hash_updates * 2
        + state_changes_count.n_modified_contracts * 2;
    let manual_blob_gas_usage =
        on_chain_data_segment_length * eth_gas_constants::DATA_GAS_PER_FIELD_ELEMENT;

    assert_eq!(manual_blob_gas_usage, calculate_tx_blob_gas_usage(state_changes_count, true));
}

/// This test goes over six cases. In each case, we calculate the gas usage given the parameters.
/// We then perform the same calculation manually, each time using only the relevant parameters.
/// The six cases are:
///     1. An empty transaction.
///     2. A DeployAccount transaction.
///     3. An L1 handler.
///     4. A transaction with L2-to-L1 messages.
///     5. A transaction that modifies the storage.
///     6. A combination of cases 3. 4. and 5.
// TODO(Aner, 29/01/24) Refactor with assert on GasVector objects.
// TODO(Aner, 29/01/24) Refactor to replace match with if when formatting is nicer
#[rstest]
fn test_calculate_tx_gas_usage_basic(#[values(false, true)] use_kzg_da: bool) {
    // An empty transaction (a theoretical case for sanity check).
    let empty_tx_gas_usage_vector = calculate_tx_gas_usage_vector(
        std::iter::empty(),
        StateChangesCount::default(),
        None,
        use_kzg_da,
    )
    .unwrap();
    assert_eq!(empty_tx_gas_usage_vector, GasVector { l1_gas: 0, blob_gas: 0 });

    // DeployAccount.

    let deploy_account_state_changes_count = StateChangesCount {
        n_storage_updates: 0,
        n_class_hash_updates: 1,
        n_compiled_class_hash_updates: 0,
        n_modified_contracts: 1,
    };

    // Manual calculation.
    let manual_starknet_gas_usage = 0;
    let (manual_sharp_gas_usage, manual_sharp_blob_gas_usage) = match use_kzg_da {
        true => (0, calculate_tx_blob_gas_usage(deploy_account_state_changes_count, use_kzg_da)),
        false => (get_onchain_data_cost(deploy_account_state_changes_count), 0),
    };

    let deploy_account_gas_usage_vector = calculate_tx_gas_usage_vector(
        std::iter::empty(),
        deploy_account_state_changes_count,
        None,
        use_kzg_da,
    )
    .unwrap();
    let GasVector { l1_gas: deploy_account_gas_usage, blob_gas: deploy_account_blob_gas_usage } =
        deploy_account_gas_usage_vector;
    assert_eq!(
        u128_from_usize(manual_starknet_gas_usage + manual_sharp_gas_usage).unwrap(),
        deploy_account_gas_usage,
    );
    assert_eq!(
        u128_from_usize(manual_sharp_blob_gas_usage).unwrap(),
        deploy_account_blob_gas_usage
    );

    // L1 handler.

    let l1_handler_payload_size = 4;
    let l1_handler_gas_usage_vector = calculate_tx_gas_usage_vector(
        std::iter::empty(),
        StateChangesCount::default(),
        Some(l1_handler_payload_size),
        use_kzg_da,
    )
    .unwrap();
    let GasVector { l1_gas: l1_handler_gas_usage, blob_gas: l1_handler_blob_gas_usage } =
        l1_handler_gas_usage_vector;

    // Manual calculation.
    let message_segment_length = get_message_segment_length(&[], Some(l1_handler_payload_size));
    let manual_starknet_gas_usage = message_segment_length * eth_gas_constants::GAS_PER_MEMORY_WORD
        + eth_gas_constants::GAS_PER_COUNTER_DECREASE
        + usize_from_u128(
            get_consumed_message_to_l2_emissions_cost(Some(l1_handler_payload_size)).l1_gas,
        )
        .unwrap();
    let manual_sharp_gas_usage =
        message_segment_length * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD;

    assert_eq!(
        u128_from_usize(manual_starknet_gas_usage + manual_sharp_gas_usage).unwrap(),
        l1_handler_gas_usage
    );
    assert_eq!(0, l1_handler_blob_gas_usage);

    // Any transaction with L2-to-L1 messages.

    let mut call_infos = Vec::new();

    for i in 0..4 {
        let payload_vec = vec![stark_felt!(0_u16); i];

        let call_info = CallInfo {
            execution: CallExecution {
                l2_to_l1_messages: vec![OrderedL2ToL1Message {
                    message: MessageToL1 {
                        payload: L2ToL1Payload(payload_vec),
                        ..Default::default()
                    },
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        call_infos.push(call_info);
    }

    // l2_to_l1_payload_lengths is [0, 1, 2, 3]
    let call_infos_iter = call_infos.iter();
    let l2_to_l1_payload_lengths: Vec<usize> = call_infos_iter
        .clone()
        .flat_map(|call_info| call_info.get_sorted_l2_to_l1_payload_lengths().unwrap())
        .collect();

    let l2_to_l1_state_changes_count = StateChangesCount {
        n_storage_updates: 0,
        n_class_hash_updates: 0,
        n_compiled_class_hash_updates: 0,
        n_modified_contracts: 1,
    };
    let l2_to_l1_messages_gas_usage_vector = calculate_tx_gas_usage_vector(
        call_infos_iter.clone(),
        l2_to_l1_state_changes_count,
        None,
        use_kzg_da,
    )
    .unwrap();
    let GasVector {
        l1_gas: l2_to_l1_messages_gas_usage,
        blob_gas: l2_to_l1_messages_blob_gas_usage,
    } = l2_to_l1_messages_gas_usage_vector;

    // Manual calculation.
    let message_segment_length = get_message_segment_length(&l2_to_l1_payload_lengths, None);
    let n_l2_to_l1_messages = l2_to_l1_payload_lengths.len();
    let manual_starknet_gas_usage = message_segment_length * eth_gas_constants::GAS_PER_MEMORY_WORD
        + n_l2_to_l1_messages * eth_gas_constants::GAS_PER_ZERO_TO_NONZERO_STORAGE_SET
        + usize_from_u128(get_log_message_to_l1_emissions_cost(&l2_to_l1_payload_lengths).l1_gas)
            .unwrap();
    let manual_sharp_gas_usage = message_segment_length
        * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD
        + match use_kzg_da {
            true => 0,
            false => get_onchain_data_cost(l2_to_l1_state_changes_count),
        };
    let manual_sharp_blob_gas_usage =
        calculate_tx_blob_gas_usage(l2_to_l1_state_changes_count, use_kzg_da);

    assert_eq!(
        u128_from_usize(manual_starknet_gas_usage + manual_sharp_gas_usage).unwrap(),
        l2_to_l1_messages_gas_usage
    );
    assert_eq!(
        u128_from_usize(manual_sharp_blob_gas_usage).unwrap(),
        l2_to_l1_messages_blob_gas_usage
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
    let storage_writings_gas_usage_vector = calculate_tx_gas_usage_vector(
        std::iter::empty(),
        storage_writes_state_changes_count,
        None,
        use_kzg_da,
    )
    .unwrap();
    let GasVector { l1_gas: storage_writings_gas_usage, blob_gas: storage_writings_blob_gas_usage } =
        storage_writings_gas_usage_vector;

    // Manual calculation.
    let (manual_starknet_gas_usage, manual_starknet_blob_gas_usage) = (0, 0);
    let (manual_sharp_gas_usage, manual_sharp_blob_gas_usage) = match use_kzg_da {
        true => (0, calculate_tx_blob_gas_usage(storage_writes_state_changes_count, use_kzg_da)),
        false => (get_onchain_data_cost(storage_writes_state_changes_count), 0),
    };

    assert_eq!(
        u128_from_usize(manual_starknet_gas_usage + manual_sharp_gas_usage).unwrap(),
        storage_writings_gas_usage
    );
    assert_eq!(
        u128_from_usize(manual_starknet_blob_gas_usage + manual_sharp_blob_gas_usage).unwrap(),
        storage_writings_blob_gas_usage
    );

    // Combined case of an L1 handler, L2-to-L1 messages and storage writes.
    let combined_state_changes_count = StateChangesCount {
        n_storage_updates: storage_writes_state_changes_count.n_storage_updates,
        n_class_hash_updates: 0,
        n_compiled_class_hash_updates: 0,
        n_modified_contracts: storage_writes_state_changes_count.n_modified_contracts
            + l2_to_l1_state_changes_count.n_modified_contracts,
    };
    let gas_usage_vector = calculate_tx_gas_usage_vector(
        call_infos_iter,
        combined_state_changes_count,
        Some(l1_handler_payload_size),
        use_kzg_da,
    )
    .unwrap();
    let GasVector { l1_gas, blob_gas } = gas_usage_vector;

    // Manual calculation.
    let fee_balance_discount = match use_kzg_da {
        true => 0,
        false => {
            eth_gas_constants::GAS_PER_MEMORY_WORD - eth_gas_constants::get_calldata_word_cost(12)
        }
    };

    let expected_gas_usage = l1_handler_gas_usage
        + l2_to_l1_messages_gas_usage
        + storage_writings_gas_usage
        // l2_to_l1_messages_gas_usage and storage_writings_gas_usage got a discount each, while
        // the combined calculation got it once.
        + u128_from_usize(fee_balance_discount).unwrap();
    let expected_blob_gas_usage =
        u128_from_usize(calculate_tx_blob_gas_usage(combined_state_changes_count, use_kzg_da))
            .unwrap();

    assert_eq!(l1_gas, expected_gas_usage);
    assert_eq!(blob_gas, expected_blob_gas_usage);
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
