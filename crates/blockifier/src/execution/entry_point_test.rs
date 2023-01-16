use pretty_assertions::assert_eq;
use starknet_api::core::EntryPointSelector;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, stark_felt};

use crate::abi::abi_utils::get_selector;
use crate::execution::entry_point::{CallEntryPoint, CallExecution, Retdata};
use crate::retdata;
use crate::state::cached_state::{CachedState, DictStateReader};
use crate::test_utils::{
    create_security_test_state, create_test_state, trivial_external_entry_point,
};

#[test]
fn test_entry_point_without_arg() {
    let mut state = create_test_state();
    let entry_point_call = CallEntryPoint {
        entry_point_selector: get_selector("without_arg"),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![] }
    );
}

#[test]
fn test_entry_point_with_arg() {
    let mut state = create_test_state();
    let calldata = calldata![stark_felt!(25)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: get_selector("with_arg"),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![] }
    );
}

#[test]
fn test_entry_point_with_builtin() {
    let mut state = create_test_state();
    let calldata = calldata![stark_felt!(47), stark_felt!(31)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: get_selector("bitwise_and"),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![] }
    );
}

#[test]
fn test_entry_point_with_hint() {
    let mut state = create_test_state();
    let calldata = calldata![stark_felt!(81)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: get_selector("sqrt"),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![] }
    );
}

#[test]
fn test_entry_point_with_return_value() {
    let mut state = create_test_state();
    let calldata = calldata![stark_felt!(23)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: get_selector("return_result"),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![stark_felt!(23)] }
    );
}

#[test]
fn test_entry_point_not_found_in_contract() {
    let mut state = create_test_state();
    let entry_point_call = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(2)),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        format!("Entry point {:#?} not found in contract.", entry_point_call.entry_point_selector),
        format!("{}", entry_point_call.execute_directly(&mut state).unwrap_err())
    );
}

#[test]
fn test_storage_var() {
    let mut state = create_test_state();
    let entry_point_call = CallEntryPoint {
        entry_point_selector: get_selector("test_storage_var"),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![] }
    );
}

#[test]
fn test_security_failure() {
    let mut state = create_security_test_state();

    fn run_security_test(
        expected_error: &str,
        entry_point_name: &str,
        calldata: Calldata,
        state: &mut CachedState<DictStateReader>,
    ) {
        let entry_point_selector = get_selector(entry_point_name);
        let entry_point_call =
            CallEntryPoint { entry_point_selector, calldata, ..trivial_external_entry_point() };
        let error = entry_point_call.execute_directly(state).unwrap_err().to_string();
        assert!(error.contains(expected_error))
    }

    for perform_inner_call_to_foo in 0..2 {
        let calldata = calldata![stark_felt!(perform_inner_call_to_foo)];
        run_security_test(
            "Custom Hint Error: Out of range",
            "test_read_bad_address",
            calldata,
            &mut state,
        )
    }
}
