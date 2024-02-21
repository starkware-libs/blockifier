use pretty_assertions::assert_eq;
use rstest::{fixture, rstest};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{EventContent, EventData, EventKey};

use crate::abi::constants;
use crate::execution::call_info::{CallExecution, CallInfo, OrderedEvent};
use crate::fee::eth_gas_constants;
use crate::fee::gas_usage::{get_da_gas_cost, get_message_segment_length, get_tx_events_gas_cost};
use crate::state::cached_state::StateChangesCount;
use crate::transaction::objects::GasVector;
use crate::utils::u128_from_usize;
use crate::versioned_constants::VersionedConstants;
#[fixture]
fn versioned_constants() -> &'static VersionedConstants {
    VersionedConstants::latest_constants()
}

#[rstest]
fn test_get_event_gas_cost(versioned_constants: &VersionedConstants) {
    let l2_resource_gas_costs = &versioned_constants.l2_resource_gas_costs;
    let (event_key_factor, data_word_cost) =
        (l2_resource_gas_costs.event_key_factor, l2_resource_gas_costs.milligas_per_data_felt);

    let call_info_1 = &CallInfo::default();
    let call_info_2 = &CallInfo::default();
    let call_info_3 = &CallInfo::default();
    let call_infos = call_info_1.into_iter().chain(call_info_2).chain(call_info_3);
    assert_eq!(GasVector::default(), get_tx_events_gas_cost(call_infos, versioned_constants));

    let create_event = |keys_size: usize, data_size: usize| OrderedEvent {
        order: 0,
        event: EventContent {
            keys: vec![EventKey(StarkFelt::ZERO); keys_size],
            data: EventData(vec![StarkFelt::ZERO; data_size]),
        },
    };
    let call_info_1 = &CallInfo {
        execution: CallExecution {
            events: vec![create_event(1, 2), create_event(1, 2)],
            ..Default::default()
        },
        ..Default::default()
    };
    let call_info_2 = &CallInfo {
        execution: CallExecution {
            events: vec![create_event(1, 0), create_event(0, 1)],
            ..Default::default()
        },
        ..Default::default()
    };
    let call_info_3 = &CallInfo {
        execution: CallExecution { events: vec![create_event(0, 1)], ..Default::default() },
        inner_calls: vec![CallInfo {
            execution: CallExecution { events: vec![create_event(1, 0)], ..Default::default() },
            ..Default::default()
        }],
        ..Default::default()
    };
    let call_infos = call_info_1.into_iter().chain(call_info_2).chain(call_info_3);
    let expected = GasVector {
        // 4 keys and 6 data words overall.
        l1_gas: (event_key_factor * data_word_cost * 4_u128 + data_word_cost * 6_u128) / 1000,
        l1_data_gas: 0_u128,
    };
    let gas_vector = get_tx_events_gas_cost(call_infos, versioned_constants);
    assert_eq!(expected, gas_vector);
    assert_ne!(GasVector::default(), gas_vector)
}

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
fn test_get_da_gas_cost_basic(#[case] state_changes_count: StateChangesCount) {
    // Manual calculation.
    let on_chain_data_segment_length = state_changes_count.n_storage_updates * 2
        + state_changes_count.n_class_hash_updates
        + state_changes_count.n_compiled_class_hash_updates * 2
        + state_changes_count.n_modified_contracts * 2;
    let manual_blob_gas_usage =
        on_chain_data_segment_length * eth_gas_constants::DATA_GAS_PER_FIELD_ELEMENT;

    let computed_gas_vector = get_da_gas_cost(state_changes_count, true);
    assert_eq!(
        GasVector { l1_gas: 0, l1_data_gas: u128_from_usize(manual_blob_gas_usage).unwrap() },
        computed_gas_vector
    );
}

#[test]
fn test_onchain_data_discount() {
    let use_kzg_da = false;
    // Check that there's no negative cost.
    assert_eq!(get_da_gas_cost(StateChangesCount::default(), use_kzg_da).l1_gas, 0);

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

    assert_eq!(
        get_da_gas_cost(state_changes_count, use_kzg_da).l1_gas,
        expected_cost.try_into().unwrap()
    );

    // Test 10% discount.
    let state_changes_count =
        StateChangesCount { n_storage_updates: 27, ..StateChangesCount::default() };

    let cost_without_discount = (state_changes_count.n_storage_updates * 2) * (512 + 100);
    let actual_cost = get_da_gas_cost(state_changes_count, use_kzg_da).l1_gas;
    let cost_ratio = (actual_cost as f64) / (cost_without_discount as f64);
    assert!(cost_ratio <= 0.9);
    assert!(cost_ratio >= 0.88);
}

#[rstest]
#[case(vec![10, 20, 30], Some(50))]
#[case(vec![10, 20, 30], None)]
#[case(vec![], Some(50))]
#[case(vec![], None)]
fn test_get_message_segment_length(
    #[case] l2_to_l1_payload_lengths: Vec<usize>,
    #[case] l1_handler_payload_size: Option<usize>,
) {
    let result = get_message_segment_length(&l2_to_l1_payload_lengths, l1_handler_payload_size);

    let expected_result: usize = l2_to_l1_payload_lengths.len()
        * constants::L2_TO_L1_MSG_HEADER_SIZE
        + l2_to_l1_payload_lengths.iter().sum::<usize>()
        + if let Some(size) = l1_handler_payload_size {
            constants::L1_TO_L2_MSG_HEADER_SIZE + size
        } else {
            0
        };

    assert_eq!(result, expected_result);
}
