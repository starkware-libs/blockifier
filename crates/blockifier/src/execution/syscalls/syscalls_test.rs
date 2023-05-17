use std::collections::{HashMap, HashSet};

use cairo_vm::vm::runners::builtin_runner::RANGE_CHECK_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use itertools::concat;
use pretty_assertions::assert_eq;
use starknet_api::core::{ClassHash, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, EthAddress, EventContent, EventData, EventKey, L2ToL1Payload,
};
use starknet_api::{calldata, patricia_key, stark_felt};

use crate::abi::abi_utils::selector_from_name;
use crate::execution::entry_point::{
    CallEntryPoint, CallExecution, CallInfo, CallType, MessageToL1, OrderedEvent,
    OrderedL2ToL1Message, Retdata,
};
use crate::retdata;
use crate::state::state_api::StateReader;
use crate::test_utils::{
    create_test_cairo1_state, trivial_external_entry_point, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS,
};

#[test]
fn test_storage_read_write() {
    let mut state = create_test_cairo1_state();

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
        CallExecution::from_retdata(retdata![stark_felt!(value)])
    );
    // Verify that the state has changed.
    let value_from_state =
        state.get_storage_at(storage_address, StorageKey::try_from(key).unwrap()).unwrap();
    assert_eq!(value_from_state, value);
}

#[test]
fn test_call_contract() {
    let mut state = create_test_cairo1_state();

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
        CallExecution::from_retdata(retdata![stark_felt!(48_u8)])
    );
}

#[test]
fn test_emit_event() {
    let mut state = create_test_cairo1_state();

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
        CallExecution { events: vec![OrderedEvent { order: 0, event }], ..Default::default() }
    );
}

#[test]
fn test_get_execution_info() {
    let mut state = create_test_cairo1_state();

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
    let mut state = create_test_cairo1_state();

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
        CallExecution::from_retdata(retdata![stark_felt!(91_u16)])
    );
}

#[test]
fn test_nested_library_call() {
    let mut state = create_test_cairo1_state();

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
        ..trivial_external_entry_point()
    };
    let nested_storage_entry_point = CallEntryPoint {
        entry_point_selector: inner_entry_point_selector,
        calldata: calldata![stark_felt!(key + 1), stark_felt!(value + 1)],
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        code_address: None,
        call_type: CallType::Delegate,
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
        ..trivial_external_entry_point()
    };
    let storage_entry_point = CallEntryPoint {
        calldata: calldata![stark_felt!(key), stark_felt!(value)],
        ..nested_storage_entry_point
    };
    let storage_entry_point_vm_resources = VmExecutionResources {
        n_steps: 148,
        n_memory_holes: 2,
        builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 5)]),
    };
    let nested_storage_call_info = CallInfo {
        call: nested_storage_entry_point,
        execution: CallExecution::from_retdata(retdata![stark_felt!(value + 1)]),
        vm_resources: storage_entry_point_vm_resources.clone(),
        storage_read_values: vec![stark_felt!(0_u8), stark_felt!(value + 1)],
        accessed_storage_keys: HashSet::from([StorageKey(patricia_key!(key + 1))]),
        ..Default::default()
    };
    let mut library_call_vm_resources = VmExecutionResources {
        n_steps: 277,
        n_memory_holes: 2,
        builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 8)]),
    };
    library_call_vm_resources += &storage_entry_point_vm_resources;
    let library_call_info = CallInfo {
        call: library_entry_point,
        execution: CallExecution::from_retdata(retdata![stark_felt!(value + 1)]),
        vm_resources: library_call_vm_resources.clone(),
        inner_calls: vec![nested_storage_call_info],
        ..Default::default()
    };
    let storage_call_info = CallInfo {
        call: storage_entry_point,
        execution: CallExecution::from_retdata(retdata![stark_felt!(value)]),
        vm_resources: storage_entry_point_vm_resources.clone(),
        storage_read_values: vec![stark_felt!(0_u8), stark_felt!(value)],
        accessed_storage_keys: HashSet::from([StorageKey(patricia_key!(key))]),
        ..Default::default()
    };

    let mut main_call_vm_resources = VmExecutionResources {
        n_steps: 368,
        n_memory_holes: 4,
        builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 10)]),
    };
    main_call_vm_resources += &library_call_vm_resources;
    let expected_call_info = CallInfo {
        call: main_entry_point.clone(),
        execution: CallExecution::from_retdata(retdata![stark_felt!(value)]),
        vm_resources: main_call_vm_resources,
        inner_calls: vec![library_call_info, storage_call_info],
        ..Default::default()
    };

    assert_eq!(main_entry_point.execute_directly(&mut state).unwrap(), expected_call_info);
}

#[test]
fn test_send_message_to_l1() {
    let mut state = create_test_cairo1_state();

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
            ..Default::default()
        }
    );
}
