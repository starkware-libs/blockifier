use pretty_assertions::assert_eq;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkHash;
use starknet_api::shash;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::CallData;

use crate::execution::entry_point::{CallEntryPoint, CallExecution, CallInfo};
use crate::test_utils::{
    create_test_state, BITWISE_AND_SELECTOR, GET_VALUE_SELECTOR, RETURN_RESULT_SELECTOR,
    SQRT_SELECTOR, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS, TEST_LIBRARY_CALL_SELECTOR,
    WITHOUT_ARG_SELECTOR, WITH_ARG_SELECTOR,
};

fn trivial_external_entrypoint() -> CallEntryPoint {
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
    let state = create_test_state();
    let entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(WITHOUT_ARG_SELECTOR)),
        ..trivial_external_entrypoint()
    };
    let expected_call_info = CallInfo {
        call: entry_point.clone(),
        execution: CallExecution { retdata: vec![] },
        inner_calls: vec![],
    };
    assert_eq!(entry_point.execute(state).unwrap(), expected_call_info);
}

#[test]
fn test_entry_point_without_arg() {
    let state = create_test_state();
    let entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(WITHOUT_ARG_SELECTOR)),
        ..trivial_external_entrypoint()
    };
    assert_eq!(entry_point.execute(state).unwrap().execution, CallExecution { retdata: vec![] });
}

#[test]
fn test_entry_point_with_arg() {
    let state = create_test_state();
    let calldata = CallData(vec![shash!(25)]);
    let entry_point = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(WITH_ARG_SELECTOR)),
        ..trivial_external_entrypoint()
    };
    assert_eq!(entry_point.execute(state).unwrap().execution, CallExecution { retdata: vec![] });
}

#[test]
fn test_entry_point_with_builtin() {
    let state = create_test_state();
    let calldata = CallData(vec![shash!(47), shash!(31)]);
    let entry_point = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(BITWISE_AND_SELECTOR)),
        ..trivial_external_entrypoint()
    };
    assert_eq!(entry_point.execute(state).unwrap().execution, CallExecution { retdata: vec![] });
}

#[test]
fn test_entry_point_with_hint() {
    let state = create_test_state();
    let calldata = CallData(vec![shash!(81)]);
    let entry_point = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(SQRT_SELECTOR)),
        ..trivial_external_entrypoint()
    };
    assert_eq!(entry_point.execute(state).unwrap().execution, CallExecution { retdata: vec![] });
}

#[test]
fn test_entry_point_with_return_value() {
    let state = create_test_state();
    let calldata = CallData(vec![shash!(23)]);
    let entry_point = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(RETURN_RESULT_SELECTOR)),
        ..trivial_external_entrypoint()
    };
    assert_eq!(
        entry_point.execute(state).unwrap().execution,
        CallExecution { retdata: vec![shash!(23)] }
    );
}

#[test]
fn test_entry_point_not_found_in_contract() {
    let state = create_test_state();
    let entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(2)),
        ..trivial_external_entrypoint()
    };
    assert_eq!(
        format!("Entry point {:#?} not found in contract.", entry_point.entry_point_selector),
        format!("{}", entry_point.execute(state).unwrap_err())
    );
}

#[test]
fn test_entry_point_with_syscall() {
    let state = create_test_state();
    let calldata = CallData(vec![shash!(1234)]);
    let entry_point = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(GET_VALUE_SELECTOR)),
        ..trivial_external_entrypoint()
    };
    assert_eq!(
        entry_point.execute(state).unwrap().execution,
        CallExecution { retdata: vec![shash!(18)] }
    );
}

#[test]
fn test_entry_point_with_library_call() {
    let state = create_test_state();
    let calldata = CallData(vec![
        shash!(TEST_CLASS_HASH),        // Class hash.
        shash!(RETURN_RESULT_SELECTOR), // Function selector.
        shash!(1),                      // Calldata length.
        shash!(91),                     // Calldata.
    ]);
    let entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(TEST_LIBRARY_CALL_SELECTOR)),
        calldata,
        ..trivial_external_entrypoint()
    };
    // TODO(AlonH, 21/12/2022): Compare the whole CallInfo.
    assert_eq!(entry_point.execute(state).unwrap().execution.retdata, vec![shash!(91)]);
}
