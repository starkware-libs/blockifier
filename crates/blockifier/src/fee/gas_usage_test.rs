use pretty_assertions::assert_eq;
use rstest::{fixture, rstest};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{EventContent, EventData, EventKey};

use crate::execution::call_info::{CallExecution, CallInfo, OrderedEvent};
use crate::fee::eth_gas_constants;
use crate::fee::gas_usage::{get_da_gas_cost, get_tx_events_gas_cost};
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
    let (key_factor, data_word_factor) = versioned_constants.get_event_milligas_cost();

    let call_infos = vec![CallInfo::default(), CallInfo::default(), CallInfo::default()];
    assert_eq!(
        GasVector::default(),
        get_tx_events_gas_cost(call_infos.iter(), versioned_constants)
    );

    let call_infos = vec![
        CallInfo {
            execution: CallExecution {
                events: vec![
                    OrderedEvent {
                        order: 0,
                        event: EventContent {
                            keys: vec![EventKey(StarkFelt::ZERO)],
                            data: EventData(vec![StarkFelt::ZERO, StarkFelt::ONE]),
                        },
                    },
                    OrderedEvent {
                        order: 0,
                        event: EventContent {
                            keys: vec![EventKey(StarkFelt::ZERO)],
                            data: EventData(vec![StarkFelt::ZERO, StarkFelt::ONE]),
                        },
                    },
                ],
                ..Default::default()
            },
            ..Default::default()
        },
        CallInfo {
            execution: CallExecution {
                events: vec![
                    OrderedEvent {
                        order: 0,
                        event: EventContent {
                            keys: vec![EventKey(StarkFelt::ZERO)],
                            data: EventData(vec![]),
                        },
                    },
                    OrderedEvent {
                        order: 0,
                        event: EventContent {
                            keys: vec![],
                            data: EventData(vec![StarkFelt::ZERO]),
                        },
                    },
                ],
                ..Default::default()
            },
            ..Default::default()
        },
        CallInfo {
            execution: CallExecution {
                events: vec![
                    OrderedEvent {
                        order: 0,
                        event: EventContent {
                            keys: vec![],
                            data: EventData(vec![StarkFelt::ZERO]),
                        },
                    },
                    OrderedEvent {
                        order: 0,
                        event: EventContent {
                            keys: vec![EventKey(StarkFelt::ZERO)],
                            data: EventData(vec![]),
                        },
                    },
                ],
                ..Default::default()
            },
            ..Default::default()
        },
    ];
    let expected = GasVector {
        // 4 keys and 6 data words overall.
        l1_gas: (key_factor * 4_u128 + data_word_factor * 6_u128) / 1000,
        l1_data_gas: 0_u128,
    };
    let gas_vector = get_tx_events_gas_cost(call_infos.iter(), versioned_constants);
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
