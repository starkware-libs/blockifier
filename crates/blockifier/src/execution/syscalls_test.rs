use pretty_assertions::assert_eq;
use starknet_api::core::{
    calculate_contract_address, ClassHash, ContractAddress, EntryPointSelector, PatriciaKey,
};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, patricia_key, stark_felt};
use test_case::test_case;

use crate::execution::entry_point::{CallEntryPoint, CallExecution, CallInfo, Retdata};
use crate::retdata;
use crate::state::state_api::State;
use crate::test_utils::{
    create_deploy_test_state, create_test_state, trivial_external_entry_point,
    TEST_CALL_CONTRACT_SELECTOR, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS, TEST_DEPLOY_SELECTOR,
    TEST_EMPTY_CONTRACT_CLASS_HASH, TEST_LIBRARY_CALL_SELECTOR, TEST_NESTED_LIBRARY_CALL_SELECTOR,
    TEST_STORAGE_READ_WRITE_SELECTOR,
};

#[test]
fn test_storage_read_write() {
    let mut state = create_test_state();
    let key = stark_felt!(1234);
    let value = stark_felt!(18);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(stark_felt!(TEST_STORAGE_READ_WRITE_SELECTOR)),
        ..trivial_external_entry_point()
    };
    let storage_address = entry_point_call.storage_address;
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![stark_felt!(value)] }
    );
    // Verify that the state has changed.
    let value_from_state = *state.get_storage_at(storage_address, key.try_into().unwrap()).unwrap();
    assert_eq!(value_from_state, value);
}

#[test]
fn test_library_call() {
    let mut state = create_test_state();
    let calldata = calldata![
        stark_felt!(TEST_CLASS_HASH),                  // Class hash.
        stark_felt!(TEST_STORAGE_READ_WRITE_SELECTOR), // Function selector.
        stark_felt!(2),                                // Calldata length.
        stark_felt!(1234),                             // Calldata: address.
        stark_felt!(91)                                // Calldata: value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(TEST_LIBRARY_CALL_SELECTOR)),
        calldata,
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![stark_felt!(91)] }
    );
}

#[test]
fn test_nested_library_call() {
    let mut state = create_test_state();
    let (key, value) = (255, 44);
    let calldata = calldata![
        stark_felt!(TEST_CLASS_HASH),                  // Class hash.
        stark_felt!(TEST_LIBRARY_CALL_SELECTOR),       // Library call function selector.
        stark_felt!(TEST_STORAGE_READ_WRITE_SELECTOR), // Storage function selector.
        stark_felt!(2),                                // Calldata length.
        stark_felt!(key),                              // Calldata: address.
        stark_felt!(value)                             // Calldata: value.
    ];

    // Create expected call info tree.
    let main_entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(TEST_NESTED_LIBRARY_CALL_SELECTOR)),
        calldata,
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        ..trivial_external_entry_point()
    };
    let nested_storage_entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(TEST_STORAGE_READ_WRITE_SELECTOR)),
        calldata: calldata![stark_felt!(key + 1), stark_felt!(value + 1)],
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        ..trivial_external_entry_point()
    };
    let library_entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(TEST_LIBRARY_CALL_SELECTOR)),
        calldata: calldata![
            stark_felt!(TEST_CLASS_HASH),                  // Class hash.
            stark_felt!(TEST_STORAGE_READ_WRITE_SELECTOR), // Storage function selector.
            stark_felt!(2),                                // Calldata length.
            stark_felt!(key + 1),                          // Calldata: address.
            stark_felt!(value + 1)                         // Calldata: value.
        ],
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        ..trivial_external_entry_point()
    };
    let storage_entry_point = CallEntryPoint {
        calldata: calldata![stark_felt!(key), stark_felt!(value)],
        ..nested_storage_entry_point.clone()
    };
    let nested_storage_call_info = CallInfo {
        call: nested_storage_entry_point,
        execution: CallExecution { retdata: retdata![stark_felt!(value + 1)] },
        ..Default::default()
    };
    let library_call_info = CallInfo {
        call: library_entry_point,
        execution: CallExecution { retdata: retdata![stark_felt!(value + 1)] },
        inner_calls: vec![nested_storage_call_info],
        ..Default::default()
    };
    let storage_call_info = CallInfo {
        call: storage_entry_point,
        execution: CallExecution { retdata: retdata![stark_felt!(value)] },
        ..Default::default()
    };
    let expected_call_info = CallInfo {
        call: main_entry_point.clone(),
        execution: CallExecution { retdata: retdata![stark_felt!(0)] },
        inner_calls: vec![library_call_info, storage_call_info],
        ..Default::default()
    };

    assert_eq!(main_entry_point.execute_directly(&mut state).unwrap(), expected_call_info);
}

#[test]
fn test_call_contract() {
    let mut state = create_test_state();
    let calldata = calldata![
        stark_felt!(TEST_CONTRACT_ADDRESS),            // Contract address.
        stark_felt!(TEST_STORAGE_READ_WRITE_SELECTOR), // Function selector.
        stark_felt!(2),                                // Calldata length.
        stark_felt!(405),                              // Calldata: address.
        stark_felt!(48)                                // Calldata: value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(TEST_CALL_CONTRACT_SELECTOR)),
        calldata,
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![stark_felt!(48)] }
    );
}

#[test_case(
    ClassHash(stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH)),
    &calldata![
    stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
    stark_felt!(1), // Contract_address_salt.
    stark_felt!(0), // Calldata length.
    stark_felt!(0) // deploy_from_zero.
    ],
    &calldata![],
    "" ;
    "No constructor: Positive flow")]
#[test_case(
    ClassHash(stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH)),
    &calldata![
        stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
        stark_felt!(1), // Contract_address_salt.
        stark_felt!(2), // Calldata length.
        stark_felt!(2), // Calldata: address.
        stark_felt!(1), // Calldata: value.
        stark_felt!(0) // deploy_from_zero.
    ],
    &calldata![
        stark_felt!(2), // Calldata: address.
        stark_felt!(1) // Calldata: value.
    ],
    &format!(
        "Invalid input: calldata length: {:?}; Cannot pass calldata to a contract with no constructor.",
        StarkFelt::from(2)
    );
    "No constructor: Negative flow - nonempty calldata")]
#[test_case(
    ClassHash(stark_felt!(TEST_CLASS_HASH)),
    &calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        stark_felt!(1), // Contract_address_salt.
        stark_felt!(2), // Calldata length.
        stark_felt!(1), // Calldata: address.
        stark_felt!(1), // Calldata: value.
        stark_felt!(0) // deploy_from_zero.
    ],
    &calldata![
        stark_felt!(1), // Calldata: address.
        stark_felt!(1) // Calldata: value.
    ],
    "";
    "With constructor: Positive flow")]
#[test_case(
    ClassHash(stark_felt!(TEST_CLASS_HASH)),
    &calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        stark_felt!(1), // Contract_address_salt.
        stark_felt!(2), // Calldata length.
        stark_felt!(3), // Calldata: address.
        stark_felt!(3), // Calldata: value.
        stark_felt!(0) // deploy_from_zero.
    ],
    &calldata![
        stark_felt!(3), // Calldata: address.
        stark_felt!(3) // Calldata: value.
    ],
    "is unavailable for deployment.";
    "With constructor: Negative flow: deploy to the same address")]
#[test_case(
    ClassHash(stark_felt!(TEST_CLASS_HASH)),
    &calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        stark_felt!(1), // Contract_address_salt.
        stark_felt!(2), // Calldata length.
        stark_felt!(1), // Calldata: address.
        stark_felt!(1), // Calldata: value.
        stark_felt!(2) // deploy_from_zero.
    ],
    &calldata![
        stark_felt!(1), // Calldata: address.
        stark_felt!(1) // Calldata: value.
    ],
    &format!(
        "Invalid syscall input: {:?}; {:}",
        stark_felt!(2),
        "The deploy_from_zero field in the deploy system call must be 0 or 1.",
    );
    "With constructor: Negative flow: illegal value for deploy_from_zero")]
fn test_deploy(
    class_hash: ClassHash,
    calldata: &Calldata,
    constructor_calldata: &Calldata,
    expected_error: &str,
) {
    let mut state = create_deploy_test_state();
    let entry_point_call = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(TEST_DEPLOY_SELECTOR)),
        calldata: calldata.clone(),
        ..trivial_external_entry_point()
    };

    if !expected_error.is_empty() {
        let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
        assert!(error.contains(expected_error));
        return;
    }

    let contract_address = calculate_contract_address(
        stark_felt!(1),
        class_hash,
        constructor_calldata,
        ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS)),
    )
    .unwrap();
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![*contract_address.0.key()] }
    );
    assert_eq!(*state.get_class_hash_at(contract_address).unwrap(), class_hash);
}
