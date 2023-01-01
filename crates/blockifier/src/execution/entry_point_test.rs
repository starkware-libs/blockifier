use pretty_assertions::assert_eq;
use starknet_api::core::EntryPointSelector;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, stark_felt};

use crate::abi::abi_utils::get_selector_from_name;
use crate::execution::entry_point::{CallEntryPoint, CallExecution, CallInfo, Retdata};
use crate::retdata;
use crate::state::cached_state::{CachedState, DictStateReader};
use crate::test_utils::{
    create_security_test_state, create_test_state, trivial_external_entry_point,
    BITWISE_AND_SELECTOR, RETURN_RESULT_SELECTOR, SQRT_SELECTOR, TEST_STORAGE_VAR_SELECTOR,
    WITHOUT_ARG_SELECTOR, WITH_ARG_SELECTOR,
};

#[test]
fn test_call_info() {
    let mut state = create_test_state();
    let entry_point_call = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(WITHOUT_ARG_SELECTOR)),
        ..trivial_external_entry_point()
    };
    let expected_call_info = CallInfo {
        call: entry_point_call.clone(),
        execution: CallExecution { retdata: retdata![] },
        ..Default::default()
    };
    assert_eq!(entry_point_call.execute_directly(&mut state).unwrap(), expected_call_info);
}

#[test]
fn test_entry_point_without_arg() {
    let mut state = create_test_state();
    let entry_point_call = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(WITHOUT_ARG_SELECTOR)),
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
        entry_point_selector: EntryPointSelector(stark_felt!(WITH_ARG_SELECTOR)),
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
        entry_point_selector: EntryPointSelector(stark_felt!(BITWISE_AND_SELECTOR)),
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
        entry_point_selector: EntryPointSelector(stark_felt!(SQRT_SELECTOR)),
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
        entry_point_selector: EntryPointSelector(stark_felt!(RETURN_RESULT_SELECTOR)),
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
        format!("Entry point {:?} not found in contract.", entry_point_call.entry_point_selector),
        format!("{}", entry_point_call.execute_directly(&mut state).unwrap_err())
    );
}

#[test]
fn test_storage_var() {
    let mut state = create_test_state();
    let entry_point_call = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(TEST_STORAGE_VAR_SELECTOR)),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![] }
    );
}

/// Tests scenarios that could fail the OS run and therefore must be caught in the blockifier.
#[test]
fn test_security_failure() {
    let mut state = create_security_test_state();

    fn run_security_test(
        expected_error: &str,
        entry_point_name: &str,
        calldata: Option<Calldata>,
        state: &mut CachedState<DictStateReader>,
    ) {
        let entry_point_selector = get_selector_from_name(entry_point_name);
        let calldata = match calldata {
            Some(data) => data,
            None => calldata![],
        };
        let entry_point_call =
            CallEntryPoint { entry_point_selector, calldata, ..trivial_external_entry_point() };
        let error = match entry_point_call.execute_directly(state) {
            Err(error) => error.to_string(),
            Ok(_) => panic!(
                "Entry point '{entry_point_name}' did not fail! Expected error: {expected_error}"
            ),
        };
        if !error.contains(expected_error) {
            panic!("Expected error: {expected_error}.\nGot: {error}")
        }
    }

    for perform_inner_call_to_foo in 0..2 {
        let calldata = calldata![stark_felt!(perform_inner_call_to_foo)];
        run_security_test(
            "Custom Hint Error: Out of range",
            "test_read_bad_address",
            Some(calldata.clone()),
            &mut state,
        );

        run_security_test(
            "Custom Hint Error: Expected integer",
            "test_relocatable_storage_address",
            Some(calldata),
            &mut state,
        );
    }

    let calldata = calldata![stark_felt!(1), stark_felt!(1)];
    run_security_test(
        "Validation failed: Read-only segments",
        "test_out_of_bounds_write_to_calldata_segment",
        Some(calldata),
        &mut state,
    );

    run_security_test(
        "Validation failed: Syscall segment end",
        "test_bad_syscall_stop_ptr",
        None,
        &mut state,
    );

    run_security_test("Expected relocatable", "test_nonrelocatable_syscall_ptr", None, &mut state);

    run_security_test("Couldn't compute operand", "test_unknown_memory", None, &mut state);

    // TODO(AlonH, 21/12/2022): Uncomment when LC fix builtin security validation.
    // run_security_test(
    //     "Missing memory cells for range_check.",
    //     "test_builtin_hole",
    //     None,
    //     &mut state,
    // );

    run_security_test(
        "Validation failed: Invalid stop pointer for range_check",
        "test_bad_builtin_stop_ptr",
        None,
        &mut state,
    );

    run_security_test(
        "Validation failed: Syscall segment size",
        "test_access_after_syscall_stop_ptr",
        None,
        &mut state,
    );

    run_security_test(
        "Can only subtract two relocatable values of the same segment",
        "test_substraction_between_relocatables",
        None,
        &mut state,
    );

    run_security_test(
        "Cannot add two relocatable values",
        "test_relocatables_addition_failure",
        None,
        &mut state,
    );

    run_security_test(
        "op0 must be known in double dereference",
        "test_op0_unknown_double_dereference",
        None,
        &mut state,
    );

    run_security_test(
        "Inconsistent auto-deduction for builtin pedersen",
        "test_bad_pedersen_values",
        None,
        &mut state,
    );

    // TODO(AlonH, 21/12/2022): Uncomment when LC fix builtin security validation.
    // run_security_test(
    //     "Missing memory cells for pedersen",
    //     "test_missing_pedersen_values",
    //     None,
    //     &mut state,
    // );

    run_security_test(
        "Range-check validation failed, number is out of valid range",
        "test_bad_range_check_values",
        None,
        &mut state,
    );

    run_security_test("Signature not found", "test_missing_signature_hint", None, &mut state);

    // TODO(AlonH, 21/12/2022): Uncomment after LC implement add_signature hint.
    // run_security_test(
    //     "Signature hint must point to the signature builtin segment",
    //     "test_signature_hint_on_wrong_segment",
    //     None,
    //     &mut state,
    // );

    // TODO(AlonH, 21/12/2022): Make sure this can't be done without a custom hint, then delete.
    // run_security_test(
    //     "Out of bounds access to program segment",
    //     "test_write_to_program_segment",
    //     None,
    //     &mut state,
    // );

    run_security_test("Cannot exit main scope.", "test_exit_main_scope", None, &mut state);

    run_security_test(
        // TODO(AlonH, 21/12/2022): Change to correct error after LC do.
        "Tried to access a scope that no longer exist",
        "test_unbalanced_enter_scope",
        None,
        &mut state,
    );

    // TODO(Elin, 21/12/2022): Uncomment after get_tx_signature syscall is implemented.
    // run_security_test(
    //     "Validation failed: Read-only segments",
    //     "test_out_of_bounds_write_to_signature_segment",
    //     None,
    //     &mut state,
    // );

    // TODO(Elin, 21/12/2022): Uncomment after get_tx_info syscall is implemented.
    // run_security_test(
    //     "Validation failed: Read-only segments",
    //     "test_out_of_bounds_write_to_tx_info_segment",
    //     None,
    //     &mut state,
    // );

    run_security_test(
        "Validation failed: Read-only segments",
        "test_write_to_call_contract_return_value",
        None,
        &mut state,
    );

    run_security_test(
        "Requested contract address \
         ContractAddress(PatriciaKey(StarkFelt(\"\
         0x0000000000000000000000000000000000000000000000000000000000000017\"))) is not deployed",
        "test_bad_call_address",
        None,
        &mut state,
    );

    run_security_test(
        "Memory addresses must be relocatable",
        "test_bad_syscall_request_arg_type",
        None,
        &mut state,
    );

    run_security_test(
        "Entry point \
         EntryPointSelector(StarkFelt(\"\
         0x0000000000000000000000000000000000000000000000000000000000000019\")) not found in \
         contract",
        "test_bad_call_selector",
        None,
        &mut state,
    );

    run_security_test(
        // TODO(AlonH, 21/12/2022): Fix typo (exeeds) after LC do.
        "exeeds maximum offset value",
        "test_out_of_bound_memory_value",
        None,
        &mut state,
    );

    run_security_test(
        "Memory addresses must be relocatable",
        "test_non_relocatable_memory_address",
        None,
        &mut state,
    );

    run_security_test(
        // TODO(AlonH, 21/12/2022): Fix expected error message after LC implement
        // substitute_error_message_references.
        "Bad expr: {test}",
        "test_bad_expr_eval",
        None,
        &mut state,
    );

    run_security_test(
        "The deploy_from_zero field in the deploy system call must be 0 or 1.",
        "test_bad_deploy_from_zero_field",
        None,
        &mut state,
    );

    // TODO(AlonH, 21/12/2022): Uncomment after LC fix the ec_op impl.
    // run_security_test(
    //     "Cannot apply EC operation: computation reached two points with the same x coordinate",
    //     "test_ec_op_invalid_input",
    //     None,
    //     &mut state,
    // );

    // TODO(AlonH, 21/12/2022): Uncomment after LC fix the ec_op point_on_curve.
    // run_security_test(
    //     "ec_op builtin: point \\({invalid_pt_x}, {invalid_pt_y}\\) is not on the curve",
    //     "test_ec_op_point_not_on_curve",
    //     None,
    //     &mut state,
    // );
}
