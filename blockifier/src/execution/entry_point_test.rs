use pretty_assertions::assert_eq;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkHash;
use starknet_api::shash;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::CallData;

use crate::execution::entry_point::{CallEntryPoint, CallExecution, CallInfo};
use crate::test_utils::{
    create_test_state, BITWISE_AND_SELECTOR, RETURN_RESULT_SELECTOR, SQRT_SELECTOR,
    TEST_CALL_CONTRACT_SELECTOR, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS, TEST_DEPLOY_SELECTOR,
    TEST_LIBRARY_CALL_SELECTOR, TEST_NESTED_LIBRARY_CALL_SELECTOR,
    TEST_STORAGE_READ_WRITE_SELECTOR, TEST_STORAGE_VAR_SELECTOR, WITHOUT_ARG_SELECTOR,
    WITH_ARG_SELECTOR,
};

fn trivial_external_entry_point() -> CallEntryPoint {
    CallEntryPoint {
        class_hash: ClassHash(shash!(TEST_CLASS_HASH)),
        entry_point_type: EntryPointType::External,
        entry_point_selector: EntryPointSelector(shash!(0)),
        calldata: CallData(vec![]),
        storage_address: ContractAddress::try_from(shash!(TEST_CONTRACT_ADDRESS)).unwrap(),
    }
}

#[test]
fn test_call_info() {
    let mut state = create_test_state();
    let entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(WITHOUT_ARG_SELECTOR)),
        ..trivial_external_entry_point()
    };
    let expected_call_info = CallInfo {
        call: entry_point.clone(),
        execution: CallExecution { retdata: vec![] },
        inner_calls: vec![],
    };
    assert_eq!(entry_point.execute(&mut state).unwrap(), expected_call_info);
}

#[test]
fn test_entry_point_without_arg() {
    let mut state = create_test_state();
    let entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(WITHOUT_ARG_SELECTOR)),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point.execute(&mut state).unwrap().execution,
        CallExecution { retdata: vec![] }
    );
}

#[test]
fn test_entry_point_with_arg() {
    let mut state = create_test_state();
    let calldata = CallData(vec![shash!(25)]);
    let entry_point = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(WITH_ARG_SELECTOR)),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point.execute(&mut state).unwrap().execution,
        CallExecution { retdata: vec![] }
    );
}

#[test]
fn test_entry_point_with_builtin() {
    let mut state = create_test_state();
    let calldata = CallData(vec![shash!(47), shash!(31)]);
    let entry_point = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(BITWISE_AND_SELECTOR)),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point.execute(&mut state).unwrap().execution,
        CallExecution { retdata: vec![] }
    );
}

#[test]
fn test_entry_point_with_hint() {
    let mut state = create_test_state();
    let calldata = CallData(vec![shash!(81)]);
    let entry_point = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(SQRT_SELECTOR)),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point.execute(&mut state).unwrap().execution,
        CallExecution { retdata: vec![] }
    );
}

#[test]
fn test_entry_point_with_return_value() {
    let mut state = create_test_state();
    let calldata = CallData(vec![shash!(23)]);
    let entry_point = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(RETURN_RESULT_SELECTOR)),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point.execute(&mut state).unwrap().execution,
        CallExecution { retdata: vec![shash!(23)] }
    );
}

#[test]
fn test_entry_point_not_found_in_contract() {
    let mut state = create_test_state();
    let entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(2)),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        format!("Entry point {:#?} not found in contract.", entry_point.entry_point_selector),
        format!("{}", entry_point.execute(&mut state).unwrap_err())
    );
}

#[test]
fn test_entry_point_with_syscall() {
    let mut state = create_test_state();
    let key = shash!(1234);
    let value = shash!(18);
    let calldata = CallData(vec![key, value]);
    let entry_point = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(TEST_STORAGE_READ_WRITE_SELECTOR)),
        ..trivial_external_entry_point()
    };
    let storage_address = entry_point.storage_address;
    assert_eq!(
        entry_point.execute(&mut state).unwrap().execution,
        CallExecution { retdata: vec![value] }
    );
    // Verify that the state has changed.
    let value_from_state = *state.get_storage_at(storage_address, key.try_into().unwrap()).unwrap();
    assert_eq!(value_from_state, value);
}

#[test]
fn test_entry_point_with_library_call() {
    let mut state = create_test_state();
    let calldata = CallData(vec![
        shash!(TEST_CLASS_HASH),                  // Class hash.
        shash!(TEST_STORAGE_READ_WRITE_SELECTOR), // Function selector.
        shash!(2),                                // Calldata length.
        shash!(1234),                             // Calldata.
        shash!(91),
    ]);
    let entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(TEST_LIBRARY_CALL_SELECTOR)),
        calldata,
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point.execute(&mut state).unwrap().execution,
        CallExecution { retdata: vec![shash!(91)] }
    );
}

#[test]
fn test_entry_point_with_nested_library_call() {
    let mut state = create_test_state();
    let (key, value) = (255, 44);
    let calldata = CallData(vec![
        shash!(TEST_CLASS_HASH),                  // Class hash.
        shash!(TEST_LIBRARY_CALL_SELECTOR),       // Library call function selector.
        shash!(TEST_STORAGE_READ_WRITE_SELECTOR), // Storage function selector.
        shash!(2),                                // Calldata length.
        shash!(key),                              // Calldata.
        shash!(value),
    ]);

    // Create expected call info tree.
    let main_entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(TEST_NESTED_LIBRARY_CALL_SELECTOR)),
        calldata,
        ..trivial_external_entry_point()
    };
    let nested_storage_entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(TEST_STORAGE_READ_WRITE_SELECTOR)),
        calldata: CallData(vec![shash!(key + 1), shash!(value + 1)]),
        ..trivial_external_entry_point()
    };
    let library_entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(TEST_LIBRARY_CALL_SELECTOR)),
        calldata: CallData(vec![
            shash!(TEST_CLASS_HASH),                  // Class hash.
            shash!(TEST_STORAGE_READ_WRITE_SELECTOR), // Storage function selector.
            shash!(2),                                // Calldata length.
            shash!(key + 1),                          // Calldata.
            shash!(value + 1),
        ]),
        ..trivial_external_entry_point()
    };
    let storage_entry_point = CallEntryPoint {
        calldata: CallData(vec![shash!(key), shash!(value)]),
        ..nested_storage_entry_point.clone()
    };
    let nested_storage_call_info = CallInfo {
        call: nested_storage_entry_point,
        execution: CallExecution { retdata: vec![shash!(value + 1)] },
        inner_calls: vec![],
    };
    let library_call_info = CallInfo {
        call: library_entry_point,
        execution: CallExecution { retdata: vec![shash!(value + 1)] },
        inner_calls: vec![nested_storage_call_info],
    };
    let storage_call_info = CallInfo {
        call: storage_entry_point,
        execution: CallExecution { retdata: vec![shash!(value)] },
        inner_calls: vec![],
    };
    let expected_call_info = CallInfo {
        call: main_entry_point.clone(),
        execution: CallExecution { retdata: vec![shash!(0)] },
        inner_calls: vec![library_call_info, storage_call_info],
    };

    assert_eq!(main_entry_point.execute(&mut state).unwrap(), expected_call_info);
}

#[test]
fn test_entry_point_with_deploy() {
    let mut state = create_test_state();
    let calldata = CallData(vec![
        shash!(TEST_CLASS_HASH), // Class hash.
        shash!(1),               // Contract_address_salt.
        shash!(1),               // Calldata length.
        shash!(91),              // Calldata.
    ]);
    let entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(TEST_DEPLOY_SELECTOR)),
        calldata,
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point.execute(&mut state).unwrap().execution,
        CallExecution { retdata: vec![shash!(0)] }
    );
}

#[test]
fn test_entry_point_with_call_contract() {
    let mut state = create_test_state();
    let calldata = CallData(vec![
        shash!(TEST_CONTRACT_ADDRESS),            // Contract address.
        shash!(TEST_STORAGE_READ_WRITE_SELECTOR), // Function selector.
        shash!(2),                                // Calldata length.
        shash!(405),                              // Calldata.
        shash!(48),
    ]);
    let entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(TEST_CALL_CONTRACT_SELECTOR)),
        calldata,
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point.execute(&mut state).unwrap().execution,
        CallExecution { retdata: vec![shash!(48)] }
    );
}

// TODO(AlonH, 21/12/2022): Use storage_var with arguments after hint is implemented.
#[test]
fn test_storage_var() {
    let mut state = create_test_state();
    let entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(TEST_STORAGE_VAR_SELECTOR)),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point.execute(&mut state).unwrap().execution,
        CallExecution { retdata: vec![] }
    );
}
