use std::collections::{HashMap, HashSet};

use assert_matches::assert_matches;
use cairo_felt::Felt252;
use cairo_vm::vm::runners::builtin_runner::RANGE_CHECK_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use itertools::concat;
use pretty_assertions::assert_eq;
use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, EthAddress, EventContent, EventData, EventKey, L2ToL1Payload,
};
use starknet_api::{calldata, patricia_key, stark_felt};
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants;
use crate::execution::contract_class::ContractClassV0;
use crate::execution::entry_point::{
    CallEntryPoint, CallExecution, CallInfo, CallType, MessageToL1, OrderedEvent,
    OrderedL2ToL1Message, Retdata,
};
use crate::execution::errors::EntryPointExecutionError;
use crate::execution::syscalls::hint_processor::OUT_OF_GAS_ERROR;
use crate::retdata;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::{
    create_deploy_test_state, create_test_state, trivial_external_entry_point, TEST_CLASS_HASH,
    TEST_CONTRACT_ADDRESS, TEST_EMPTY_CONTRACT_CLASS_HASH, TEST_EMPTY_CONTRACT_PATH,
};

pub const REQUIRED_GAS_STORAGE_READ_WRITE_TEST: u64 = 35050;
pub const REQUIRED_GAS_CALL_CONTRACT_TEST: u64 = 128880;
pub const REQUIRED_GAS_LIBRARY_CALL_TEST: u64 = REQUIRED_GAS_CALL_CONTRACT_TEST;

#[test]
fn test_storage_read_write() {
    let mut state = create_test_state();

    let key = stark_felt!(1234_u16);
    let value = stark_felt!(18_u8);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        ..trivial_external_entry_point()
    };
    let storage_address = entry_point_call.storage_address;
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            retdata: retdata![stark_felt!(value)],
            gas_consumed: stark_felt!(REQUIRED_GAS_STORAGE_READ_WRITE_TEST),
            ..CallExecution::default()
        }
    );
    // Verify that the state has changed.
    let value_from_state =
        state.get_storage_at(storage_address, StorageKey::try_from(key).unwrap()).unwrap();
    assert_eq!(value_from_state, value);
}

#[test]
fn test_call_contract() {
    let mut state = create_test_state();

    let outer_entry_point_selector = selector_from_name("test_call_contract");
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let calldata = calldata![
        stark_felt!(TEST_CONTRACT_ADDRESS), // Contract address.
        inner_entry_point_selector.0,       // Function selector.
        stark_felt!(2_u8),                  // Calldata length.
        stark_felt!(405_u16),               // Calldata: address.
        stark_felt!(48_u8)                  // Calldata: value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata,
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            retdata: retdata![stark_felt!(48_u8)],
            gas_consumed: stark_felt!(REQUIRED_GAS_CALL_CONTRACT_TEST),
            ..CallExecution::default()
        }
    );
}

#[test]
fn test_emit_event() {
    let mut state = create_test_state();

    let keys = vec![stark_felt!(2019_u16), stark_felt!(2020_u16)];
    let data = vec![stark_felt!(2021_u16), stark_felt!(2022_u16), stark_felt!(2023_u16)];
    let calldata = Calldata(
        concat(vec![
            vec![stark_felt!(keys.len() as u8)],
            keys.clone(),
            vec![stark_felt!(data.len() as u8)],
            data.clone(),
        ])
        .into(),
    );
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_emit_event"),
        calldata,
        ..trivial_external_entry_point()
    };

    let event =
        EventContent { keys: keys.into_iter().map(EventKey).collect(), data: EventData(data) };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            events: vec![OrderedEvent { order: 0, event }],
            gas_consumed: stark_felt!(52970_u64),
            ..Default::default()
        }
    );
}

#[test]
fn test_get_block_hash() {
    let mut state = create_test_state();

    // Initialize block number -> block hash entry.
    let block_number = stark_felt!(1800_u64);
    let block_hash = stark_felt!(66_u64);
    let key = StorageKey::try_from(block_number).unwrap();
    let block_hash_contract_address =
        ContractAddress::try_from(StarkFelt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS)).unwrap();
    state.set_storage_at(block_hash_contract_address, key, block_hash);

    // Create call.
    let calldata = calldata![block_number];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_get_block_hash"),
        calldata,
        ..trivial_external_entry_point()
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            gas_consumed: stark_felt!(15650_u64),
            ..CallExecution::from_retdata(retdata![block_hash])
        }
    );
}

#[test]
fn test_get_execution_info() {
    let mut state = create_test_state();

    let calldata = calldata![
        // Expected block info.
        stark_felt!(1800_u16), // Block number.
        stark_felt!(1801_u16), // Block timestamp.
        stark_felt!(1802_u16), // Sequencer address.
        // Expected transaction info.
        stark_felt!(1803_u16), // Transaction version.
        stark_felt!(1804_u16), // Account address.
        stark_felt!(1805_u16), // Max fee.
        stark_felt!(1806_u16), // Chain ID.
        stark_felt!(1807_u16), // Nonce.
        // Expected call info.
        stark_felt!(1808_u16), // Caller address.
        stark_felt!(1809_u16), // Storage address.
        stark_felt!(1810_u16)  // Entry point selector.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_get_execution_info"),
        calldata,
        ..trivial_external_entry_point()
    };

    // TODO(spapini): Fix the "UNEXPECTED ERROR".
    entry_point_call.execute_directly(&mut state).unwrap_err();
}

#[test]
fn test_library_call() {
    let mut state = create_test_state();

    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let calldata = calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        inner_entry_point_selector.0, // Function selector.
        stark_felt!(2_u8),            // Calldata length.
        stark_felt!(1234_u16),        // Calldata: address.
        stark_felt!(91_u8)            // Calldata: value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_library_call"),
        calldata,
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        ..trivial_external_entry_point()
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            retdata: retdata![stark_felt!(91_u16)],
            gas_consumed: stark_felt!(REQUIRED_GAS_LIBRARY_CALL_TEST),
            ..Default::default()
        }
    );
}

#[test]
fn test_nested_library_call() {
    let mut state = create_test_state();

    let (key, value) = (255_u64, 44_u64);
    let outer_entry_point_selector = selector_from_name("test_library_call");
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let main_entry_point_calldata = calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        outer_entry_point_selector.0, // Library call function selector.
        inner_entry_point_selector.0, // Storage function selector.
        stark_felt!(key),             // Calldata: address.
        stark_felt!(value)            // Calldata: value.
    ];

    // Create expected call info tree.
    let main_entry_point = CallEntryPoint {
        entry_point_selector: selector_from_name("test_nested_library_call"),
        calldata: main_entry_point_calldata,
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        initial_gas: Felt252::from(9999906600_u64),
        ..trivial_external_entry_point()
    };
    let nested_storage_entry_point = CallEntryPoint {
        entry_point_selector: inner_entry_point_selector,
        calldata: calldata![stark_felt!(key + 1), stark_felt!(value + 1)],
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        code_address: None,
        call_type: CallType::Delegate,
        initial_gas: Felt252::from(9999719920_u64),
        ..trivial_external_entry_point()
    };
    let library_entry_point = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata: calldata![
            stark_felt!(TEST_CLASS_HASH), // Class hash.
            inner_entry_point_selector.0, // Storage function selector.
            stark_felt!(2_u8),            // Calldata: address.
            stark_felt!(key + 1),         // Calldata: address.
            stark_felt!(value + 1)        // Calldata: value.
        ],
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        code_address: None,
        call_type: CallType::Delegate,
        initial_gas: Felt252::from(9999813750_u64),
        ..trivial_external_entry_point()
    };
    let storage_entry_point = CallEntryPoint {
        calldata: calldata![stark_felt!(key), stark_felt!(value)],
        initial_gas: Felt252::from(9999623870_u64),
        ..nested_storage_entry_point
    };
    let storage_entry_point_vm_resources = VmExecutionResources {
        n_steps: 147,
        n_memory_holes: 2,
        builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 5)]),
    };
    let nested_storage_call_info = CallInfo {
        call: nested_storage_entry_point,
        execution: CallExecution {
            retdata: retdata![stark_felt!(value + 1)],
            gas_consumed: stark_felt!(REQUIRED_GAS_STORAGE_READ_WRITE_TEST),
            ..CallExecution::default()
        },
        vm_resources: storage_entry_point_vm_resources.clone(),
        storage_read_values: vec![stark_felt!(value + 1)],
        accessed_storage_keys: HashSet::from([StorageKey(patricia_key!(key + 1))]),
        ..Default::default()
    };
    let library_call_vm_resources = VmExecutionResources {
        n_steps: 419,
        n_memory_holes: 4,
        builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 13)]),
    };
    let library_call_info = CallInfo {
        call: library_entry_point,
        execution: CallExecution {
            retdata: retdata![stark_felt!(value + 1)],
            gas_consumed: stark_felt!(REQUIRED_GAS_LIBRARY_CALL_TEST),
            ..CallExecution::default()
        },
        vm_resources: library_call_vm_resources,
        inner_calls: vec![nested_storage_call_info],
        ..Default::default()
    };
    let storage_call_info = CallInfo {
        call: storage_entry_point,
        execution: CallExecution {
            retdata: retdata![stark_felt!(value)],
            gas_consumed: stark_felt!(REQUIRED_GAS_STORAGE_READ_WRITE_TEST),
            ..CallExecution::default()
        },
        vm_resources: storage_entry_point_vm_resources,
        storage_read_values: vec![stark_felt!(value)],
        accessed_storage_keys: HashSet::from([StorageKey(patricia_key!(key))]),
        ..Default::default()
    };

    let main_call_vm_resources = VmExecutionResources {
        n_steps: 781,
        n_memory_holes: 8,
        builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 23)]),
    };
    let expected_call_info = CallInfo {
        call: main_entry_point.clone(),
        execution: CallExecution {
            retdata: retdata![stark_felt!(value)],
            gas_consumed: stark_felt!(317780_u64),
            ..CallExecution::default()
        },
        vm_resources: main_call_vm_resources,
        inner_calls: vec![library_call_info, storage_call_info],
        ..Default::default()
    };

    assert_eq!(main_entry_point.execute_directly(&mut state).unwrap(), expected_call_info);
}

#[test]
fn test_replace_class() {
    let mut state = create_deploy_test_state();

    // Negative flow.

    // Replace with undeclared class hash.
    let entry_point_call = CallEntryPoint {
        calldata: calldata![stark_felt!(1234_u16)],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point()
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert!(error.contains("is not declared"));

    // Replace with Cairo 0 class hash.
    let v0_class_hash = ClassHash(stark_felt!(5678_u16));
    let v0_contract_class = ContractClassV0::from_file(TEST_EMPTY_CONTRACT_PATH).into();
    state.set_contract_class(&v0_class_hash, v0_contract_class).unwrap();

    let entry_point_call = CallEntryPoint {
        calldata: calldata![v0_class_hash.0],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point()
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert!(error.contains("Cannot replace V1 class hash with V0 class hash"));

    // Positive flow.
    let contract_address = ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS));
    let old_class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    let new_class_hash = ClassHash(stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH));
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), old_class_hash);
    let entry_point_call = CallEntryPoint {
        calldata: calldata![new_class_hash.0],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed: stark_felt!(14850_u64), ..Default::default() }
    );
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), new_class_hash);
}

#[test]
fn test_send_message_to_l1() {
    let mut state = create_test_state();

    let to_address = stark_felt!(1234_u16);
    let payload = vec![stark_felt!(2019_u16), stark_felt!(2020_u16), stark_felt!(2021_u16)];
    let calldata = Calldata(
        concat(vec![vec![to_address, stark_felt!(payload.len() as u64)], payload.clone()]).into(),
    );
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_send_message_to_l1"),
        calldata,
        ..trivial_external_entry_point()
    };

    let to_address = EthAddress::try_from(to_address).unwrap();
    let message = MessageToL1 { to_address, payload: L2ToL1Payload(payload) };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            l2_to_l1_messages: vec![OrderedL2ToL1Message { order: 0, message }],
            gas_consumed: stark_felt!(38390_u64),
            ..Default::default()
        }
    );
}

#[test_case(
    ClassHash(stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH)),
    calldata![
    stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
    ContractAddressSalt::default().0,            // Contract_address_salt.
    stark_felt!(0_u8),                           // Calldata length.
    stark_felt!(0_u8)                            // deploy_from_zero.
    ],
    calldata![],
    None ;
    "No constructor: Positive flow")]
#[test_case(
    ClassHash(stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH)),
    calldata![
        stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0,            // Contract_address_salt.
        stark_felt!(2_u8),                           // Calldata length.
        stark_felt!(2_u8),                           // Calldata: address.
        stark_felt!(1_u8),                           // Calldata: value.
        stark_felt!(0_u8)                            // deploy_from_zero.
    ],
    calldata![
        stark_felt!(2_u8),                           // Calldata: arg1.
        stark_felt!(1_u8)                            // Calldata: arg2.
    ],
    Some(
    "Invalid input: constructor_calldata; Cannot pass calldata to a contract with no constructor.");
    "No constructor: Negative flow: nonempty calldata")]
#[test_case(
    ClassHash(stark_felt!(TEST_CLASS_HASH)),
    calldata![
        stark_felt!(TEST_CLASS_HASH),     // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2_u8),                // Calldata length.
        stark_felt!(1_u8),                // Calldata: arg1.
        stark_felt!(1_u8),                // Calldata: arg2.
        stark_felt!(0_u8)                 // deploy_from_zero.
    ],
    calldata![
        stark_felt!(1_u8),                // Calldata: arg1.
        stark_felt!(1_u8)                 // Calldata: arg2.
    ],
    None;
    "With constructor: Positive flow")]
#[test_case(
    ClassHash(stark_felt!(TEST_CLASS_HASH)),
    calldata![
        stark_felt!(TEST_CLASS_HASH),     // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2_u8),                // Calldata length.
        stark_felt!(3_u8),                // Calldata: arg1.
        stark_felt!(3_u8),                // Calldata: arg2.
        stark_felt!(0_u8)                 // deploy_from_zero.
    ],
    calldata![
        stark_felt!(3_u8),                // Calldata: arg1.
        stark_felt!(3_u8)                 // Calldata: arg2.
    ],
    Some("is unavailable for deployment.");
    "With constructor: Negative flow: deploy to the same address")]
fn test_deploy(
    class_hash: ClassHash,
    calldata: Calldata,
    constructor_calldata: Calldata,
    expected_error: Option<&str>,
) {
    let mut state = create_deploy_test_state();
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_deploy"),
        calldata,
        ..trivial_external_entry_point()
    };

    if let Some(expected_error) = expected_error {
        let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
        assert!(error.contains(expected_error));
        return;
    }

    // No errors expected.
    let contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &constructor_calldata,
        ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS)),
    )
    .unwrap();
    let deploy_call = &entry_point_call.execute_directly(&mut state).unwrap().inner_calls[0];
    assert_eq!(deploy_call.call.storage_address, contract_address);
    let mut retdata = retdata![];
    let gas_consumed = if constructor_calldata.0.is_empty() {
        stark_felt!(0_u64)
    } else {
        retdata.0.push(constructor_calldata.0[0]);
        stark_felt!(17040_u64)
    };
    assert_eq!(
        deploy_call.execution,
        CallExecution {
            retdata,
            gas_consumed: stark_felt!(gas_consumed),
            ..CallExecution::default()
        }
    );
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), class_hash);
}

#[test]
fn test_out_of_gas() {
    let mut state = create_test_state();

    let key = stark_felt!(1234_u16);
    let value = stark_felt!(18_u8);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        initial_gas: Felt252::from(REQUIRED_GAS_STORAGE_READ_WRITE_TEST - 1),
        ..trivial_external_entry_point()
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err();
    assert_matches!(error, EntryPointExecutionError::ExecutionFailed{ error_data }
        if error_data == vec![stark_felt!(OUT_OF_GAS_ERROR)]);
}
