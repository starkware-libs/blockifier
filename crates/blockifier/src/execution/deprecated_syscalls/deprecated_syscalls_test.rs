use std::collections::{HashMap, HashSet};

use cairo_vm::vm::runners::builtin_runner::RANGE_CHECK_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use pretty_assertions::assert_eq;
use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Calldata, ContractAddressSalt};
use starknet_api::{calldata, patricia_key, stark_felt};
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::execution::entry_point::{CallEntryPoint, CallExecution, CallInfo, CallType, Retdata};
use crate::execution::errors::EntryPointExecutionError;
use crate::retdata;
use crate::state::state_api::StateReader;
use crate::test_utils::{
    create_deploy_test_state, create_test_state, pad_address_to_64, trivial_external_entry_point,
    SECURITY_TEST_CLASS_HASH, SECURITY_TEST_CONTRACT_ADDRESS, TEST_CLASS_HASH,
    TEST_CONTRACT_ADDRESS, TEST_CONTRACT_ADDRESS_2, TEST_EMPTY_CONTRACT_CLASS_HASH,
};

#[test]
fn test_storage_read_write() {
    let mut state = create_test_state();
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
fn test_library_call() {
    let mut state = create_test_state();
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
    let mut state = create_test_state();
    let (key, value) = (255, 44);
    let outer_entry_point_selector = selector_from_name("test_library_call");
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let main_entry_point_calldata = calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        outer_entry_point_selector.0, // Library call function selector.
        inner_entry_point_selector.0, // Storage function selector.
        stark_felt!(2),               // Calldata length.
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
            stark_felt!(2),               // Calldata length.
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
    let storage_entry_point_vm_resources =
        VmExecutionResources { n_steps: 41, ..Default::default() };
    let nested_storage_call_info = CallInfo {
        call: nested_storage_entry_point,
        execution: CallExecution::from_retdata(retdata![stark_felt!(value + 1)]),
        vm_resources: storage_entry_point_vm_resources.clone(),
        storage_read_values: vec![stark_felt!(0), stark_felt!(value + 1)],
        accessed_storage_keys: HashSet::from([StorageKey(patricia_key!(key + 1))]),
        ..Default::default()
    };
    let mut library_call_vm_resources = VmExecutionResources {
        n_steps: 38,
        builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 1)]),
        ..Default::default()
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

    // Nested library call cost: library_call(inner) + library_call(library_call(inner)).
    let mut main_call_vm_resources = VmExecutionResources { n_steps: 45, ..Default::default() };
    main_call_vm_resources += &(&library_call_vm_resources * 2);
    let expected_call_info = CallInfo {
        call: main_entry_point.clone(),
        execution: CallExecution::from_retdata(retdata![stark_felt!(0)]),
        vm_resources: main_call_vm_resources,
        inner_calls: vec![library_call_info, storage_call_info],
        ..Default::default()
    };

    assert_eq!(main_entry_point.execute_directly(&mut state).unwrap(), expected_call_info);
}

#[test]
fn test_call_contract() {
    let mut state = create_test_state();
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
fn test_replace_class() {
    // Negative flow.
    let mut state = create_deploy_test_state();
    // Replace with undeclared class hash.
    let calldata = calldata![stark_felt!(SECURITY_TEST_CLASS_HASH)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point()
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert!(error.contains("is not declared"));

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
    entry_point_call.execute_directly(&mut state).unwrap();
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), new_class_hash);
}

#[test]
fn test_stack_trace() {
    let mut state = create_test_state();
    // Nest 3 calls: test_call_contract -> test_call_contract -> assert_0_is_1.
    let outer_entry_point_selector = selector_from_name("test_call_contract");
    let inner_entry_point_selector = selector_from_name("foo");
    let calldata = calldata![
        stark_felt!(TEST_CONTRACT_ADDRESS_2), // Contract address.
        outer_entry_point_selector.0,         // Calling test_call_contract again.
        stark_felt!(3),                       /* Calldata length for inner
                                               * test_call_contract. */
        stark_felt!(SECURITY_TEST_CONTRACT_ADDRESS), // Contract address.
        inner_entry_point_selector.0,                // Function selector.
        stark_felt!(0)                               // Innermost calldata length.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata,
        ..trivial_external_entry_point()
    };
    let expected_trace = format!(
        "Error in the called contract ({}):
Error at pc=0:19:
Got an exception while executing a hint.
Cairo traceback (most recent call last):
Unknown location (pc=0:629)
Unknown location (pc=0:612)
Error in the called contract ({}):
Error at pc=0:19:
Got an exception while executing a hint.
Cairo traceback (most recent call last):
Unknown location (pc=0:629)
Unknown location (pc=0:612)
Error in the called contract ({}):
Error at pc=0:58:
An ASSERT_EQ instruction failed: 1 != 0.
Cairo traceback (most recent call last):
Unknown location (pc=0:62)",
        pad_address_to_64(TEST_CONTRACT_ADDRESS),
        pad_address_to_64(TEST_CONTRACT_ADDRESS_2),
        pad_address_to_64(SECURITY_TEST_CONTRACT_ADDRESS)
    );
    match entry_point_call.execute_directly(&mut state).unwrap_err() {
        EntryPointExecutionError::VirtualMachineExecutionErrorWithTrace { trace, source: _ } => {
            assert_eq!(trace, expected_trace)
        }
        other_error => panic!("Unexpected error type: {other_error:?}"),
    }
}

#[test_case(
    ClassHash(stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH)),
    calldata![
    stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
    ContractAddressSalt::default().0, // Contract_address_salt.
    stark_felt!(0), // Calldata length.
    stark_felt!(0) // deploy_from_zero.
    ],
    calldata![],
    None ;
    "No constructor: Positive flow")]
#[test_case(
    ClassHash(stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH)),
    calldata![
        stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2), // Calldata length.
        stark_felt!(2), // Calldata: address.
        stark_felt!(1), // Calldata: value.
        stark_felt!(0) // deploy_from_zero.
    ],
    calldata![
        stark_felt!(2), // Calldata: address.
        stark_felt!(1) // Calldata: value.
    ],
    Some(
    "Invalid input: constructor_calldata; Cannot pass calldata to a contract with no constructor.");
    "No constructor: Negative flow: nonempty calldata")]
#[test_case(
    ClassHash(stark_felt!(TEST_CLASS_HASH)),
    calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2), // Calldata length.
        stark_felt!(1), // Calldata: address.
        stark_felt!(1), // Calldata: value.
        stark_felt!(0) // deploy_from_zero.
    ],
    calldata![
        stark_felt!(1), // Calldata: address.
        stark_felt!(1) // Calldata: value.
    ],
    None;
    "With constructor: Positive flow")]
#[test_case(
    ClassHash(stark_felt!(TEST_CLASS_HASH)),
    calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2), // Calldata length.
        stark_felt!(3), // Calldata: address.
        stark_felt!(3), // Calldata: value.
        stark_felt!(0) // deploy_from_zero.
    ],
    calldata![
        stark_felt!(3), // Calldata: address.
        stark_felt!(3) // Calldata: value.
    ],
    Some("is unavailable for deployment.");
    "With constructor: Negative flow: deploy to the same address")]
#[test_case(
    ClassHash(stark_felt!(TEST_CLASS_HASH)),
    calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2), // Calldata length.
        stark_felt!(1), // Calldata: address.
        stark_felt!(1), // Calldata: value.
        stark_felt!(2) // deploy_from_zero.
    ],
    calldata![
        stark_felt!(1), // Calldata: address.
        stark_felt!(1) // Calldata: value.
    ],
    Some(&format!(
        "Invalid syscall input: {:?}; {:}",
        stark_felt!(2),
        "The deploy_from_zero field in the deploy system call must be 0 or 1.",
    ));
    "With constructor: Negative flow: illegal value for deploy_from_zero")]
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
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![*contract_address.0.key()])
    );
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), class_hash);
}
