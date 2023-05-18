use std::collections::{HashMap, HashSet};

use cairo_vm::vm::runners::builtin_runner::RANGE_CHECK_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use pretty_assertions::assert_eq;
use starknet_api::core::{ClassHash, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Calldata, EventContent, EventData, EventKey};
use starknet_api::{calldata, patricia_key, stark_felt};

use crate::abi::abi_utils::selector_from_name;
use crate::execution::entry_point::{
    CallEntryPoint, CallExecution, CallInfo, CallType, OrderedEvent, Retdata,
};
use crate::retdata;
use crate::state::state_api::StateReader;
use crate::test_utils::{
    create_test_cairo1_state, trivial_external_entry_point, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS,
};

#[test]
fn test_storage_read_write() {
    let mut state = create_test_cairo1_state();
    let key = stark_felt!(1234);
    let value = stark_felt!(18);
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
        stark_felt!(2),                     // Calldata length.
        stark_felt!(405),                   // Calldata: address.
        stark_felt!(48)                     // Calldata: value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata,
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![stark_felt!(48)])
    );
}

#[test]
fn test_emit_event() {
    dbg!("GOT HERE");
    let mut state = create_test_cairo1_state();
    let entry_point_selector = selector_from_name("test_emit_event");
    let event = EventContent {
        keys: vec![EventKey(stark_felt!(2019)), EventKey(stark_felt!(2020))],
        data: EventData(vec![stark_felt!(2021), stark_felt!(2022), stark_felt!(2023)]),
    };

    let calldata = calldata![
        stark_felt!(TEST_CONTRACT_ADDRESS), // Contract address.
        entry_point_selector.0,             // Function selector.
        stark_felt!(2),                     // Keys length.
        stark_felt!(2019),                  // Keys.
        stark_felt!(2020),
        stark_felt!(3),    // Data length.
        stark_felt!(2021), // Data.
        stark_felt!(2022), // Data.
        stark_felt!(2023)  // Data.
    ];
    let entry_point_call =
        CallEntryPoint { entry_point_selector, calldata, ..trivial_external_entry_point() };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { events: vec![OrderedEvent { order: 0, event }], ..Default::default() }
    );
}

#[test]
fn test_library_call() {
    let mut state = create_test_cairo1_state();
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let calldata = calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        inner_entry_point_selector.0, // Function selector.
        stark_felt!(2),               // Calldata length.
        stark_felt!(1234),            // Calldata: address.
        stark_felt!(91)               // Calldata: value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_library_call"),
        calldata,
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![stark_felt!(91)])
    );
}

#[test]
fn test_nested_library_call() {
    let mut state = create_test_cairo1_state();
    let (key, value) = (255, 44);
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
            stark_felt!(2),               // Calldata: address.
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
        storage_read_values: vec![stark_felt!(0), stark_felt!(value + 1)],
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
        storage_read_values: vec![stark_felt!(0), stark_felt!(value)],
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
