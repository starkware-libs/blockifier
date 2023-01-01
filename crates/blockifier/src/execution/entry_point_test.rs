use pretty_assertions::assert_eq;
use starknet_api::core::EntryPointSelector;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, stark_felt};

use crate::abi::abi_utils::selector_from_name;
use crate::execution::entry_point::{CallEntryPoint, CallExecution, CallInfo, Retdata};
use crate::retdata;
use crate::state::cached_state::CachedState;
use crate::test_utils::{
    create_security_test_state, create_test_state, trivial_external_entry_point, DictStateReader,
};

#[test]
fn test_call_info_iteration() {
    // Create nested call infos according to their expected traversal order (pre-order).
    // The tree is constructed as follows:
    //                  root (0)
    //              /             \
    //      inner_node (1)      right_leaf (3)
    //           |
    //       left_leaf (2)
    let left_leaf = CallInfo {
        call: CallEntryPoint { calldata: calldata![stark_felt!(2)], ..Default::default() },
        ..Default::default()
    };
    let right_leaf = CallInfo {
        call: CallEntryPoint { calldata: calldata![stark_felt!(3)], ..Default::default() },
        ..Default::default()
    };
    let inner_node = CallInfo {
        call: CallEntryPoint { calldata: calldata![stark_felt!(1)], ..Default::default() },
        inner_calls: vec![left_leaf],
        ..Default::default()
    };
    let root = CallInfo {
        call: CallEntryPoint { calldata: calldata![stark_felt!(0)], ..Default::default() },
        inner_calls: vec![inner_node, right_leaf],
        ..Default::default()
    };

    for (i, call_info) in root.into_iter().enumerate() {
        assert_eq!(call_info.call.calldata, calldata![stark_felt!(i as u64)]);
    }
}

#[test]
fn test_entry_point_without_arg() {
    let mut state = create_test_state();
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("without_arg"),
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
        entry_point_selector: selector_from_name("with_arg"),
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
        entry_point_selector: selector_from_name("bitwise_and"),
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
        entry_point_selector: selector_from_name("sqrt"),
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
        entry_point_selector: selector_from_name("return_result"),
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
        entry_point_selector: selector_from_name("test_storage_var"),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![] }
    );
}

/// Runs test scenarios that could fail the OS run and therefore must be caught in the Blockifier.
fn run_security_test(
    expected_error: &str,
    entry_point_name: &str,
    calldata: Calldata,
    state: &mut CachedState<DictStateReader>,
) {
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name(entry_point_name),
        calldata,
        ..trivial_external_entry_point()
    };
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

#[test]
fn test_vm_execution_security_failures() {
    let mut state = create_security_test_state();

    run_security_test(
        "Expected relocatable",
        "test_nonrelocatable_syscall_ptr",
        calldata![],
        &mut state,
    );

    run_security_test("Couldn't compute operand", "test_unknown_memory", calldata![], &mut state);

    run_security_test(
        "Can only subtract two relocatable values of the same segment",
        "test_subtraction_between_relocatables",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Cannot add two relocatable values",
        "test_relocatables_addition_failure",
        calldata![],
        &mut state,
    );

    run_security_test(
        "op0 must be known in double dereference",
        "test_op0_unknown_double_dereference",
        calldata![],
        &mut state,
    );

    // TODO(AlonH, 21/12/2022): Make sure this can't be done without a custom hint, then delete.
    // run_security_test(
    //     "Out of bounds access to program segment",
    //     "test_write_to_program_segment",
    //     calldata![],
    //     &mut state,
    // );

    run_security_test("Cannot exit main scope.", "test_exit_main_scope", calldata![], &mut state);

    run_security_test(
        "Every enter_scope() requires a corresponding exit_scope()",
        "test_missing_exit_scope",
        calldata![],
        &mut state,
    );

    run_security_test(
        "exceeds maximum offset value",
        "test_out_of_bound_memory_value",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Memory addresses must be relocatable",
        "test_non_relocatable_memory_address",
        calldata![],
        &mut state,
    );

    // TODO(AlonH, 21/12/2022): Uncomment and fix expected error message after LC implement
    // substitute_error_message_references.
    // run_security_test(
    //     "Bad expr: {test}",
    //     "test_bad_expr_eval",
    //     calldata![],
    //     &mut state,
    // );
}

#[test]
fn test_builtin_execution_security_failures() {
    let mut state = create_security_test_state();

    run_security_test(
        "Inconsistent auto-deduction for builtin pedersen",
        "test_bad_pedersen_values",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Range-check validation failed, number is out of valid range",
        "test_bad_range_check_values",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Signature not found",
        "test_missing_signature_hint",
        calldata![],
        &mut state,
    );

    // TODO(AlonH, 21/12/2022): Uncomment after LC implement add_signature hint.
    // run_security_test(
    //     "Signature hint must point to the signature builtin segment",
    //     "test_signature_hint_on_wrong_segment",
    //     calldata![],
    //     &mut state,
    // );

    // TODO(AlonH, 21/12/2022): Uncomment after LC fix the ec_op impl.
    // run_security_test(
    //     "Cannot apply EC operation: computation reached two points with the same x coordinate",
    //     "test_ec_op_invalid_input",
    //     calldata![],
    //     &mut state,
    // );

    // TODO(AlonH, 21/12/2022): Uncomment after LC fix the ec_op point_on_curve.
    // run_security_test(
    //     "ec_op builtin: point \\({invalid_pt_x}, {invalid_pt_y}\\) is not on the curve",
    //     "test_ec_op_point_not_on_curve",
    //     calldata![],
    //     &mut state,
    // );
}

#[test]
fn test_syscall_execution_security_failures() {
    let mut state = create_security_test_state();

    for perform_inner_call_to_foo in 0..2 {
        let calldata = calldata![stark_felt!(perform_inner_call_to_foo)];
        run_security_test(
            "Custom Hint Error: Out of range",
            "test_read_bad_address",
            calldata.clone(),
            &mut state,
        );

        run_security_test(
            "Custom Hint Error: Expected integer",
            "test_relocatable_storage_address",
            calldata,
            &mut state,
        );
    }

    run_security_test(
        "Requested contract address \
         ContractAddress(PatriciaKey(StarkFelt(\"\
         0x0000000000000000000000000000000000000000000000000000000000000017\"))) is not deployed",
        "test_bad_call_address",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Memory addresses must be relocatable",
        "test_bad_syscall_request_arg_type",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Entry point \
         EntryPointSelector(StarkFelt(\"\
         0x0000000000000000000000000000000000000000000000000000000000000019\")) not found in \
         contract",
        "test_bad_call_selector",
        calldata![],
        &mut state,
    );

    run_security_test(
        "The deploy_from_zero field in the deploy system call must be 0 or 1.",
        "test_bad_deploy_from_zero_field",
        calldata![],
        &mut state,
    );
}

#[test]
fn test_post_run_validation_security_failure() {
    let mut state = create_security_test_state();

    run_security_test(
        "Missing memory cells for builtin range_check",
        "test_builtin_hole",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Missing memory cells for builtin hash",
        "test_missing_pedersen_values",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Validation failed: Invalid stop pointer for range_check",
        "test_bad_builtin_stop_ptr",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Validation failed: Syscall segment size",
        "test_access_after_syscall_stop_ptr",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Validation failed: Syscall segment end",
        "test_bad_syscall_stop_ptr",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Validation failed: Read-only segments",
        "test_out_of_bounds_write_to_signature_segment",
        calldata![],
        &mut state,
    );

    // TODO(Elin, 21/12/2022): Uncomment after get_tx_info syscall is implemented.
    // run_security_test(
    //     "Validation failed: Read-only segments",
    //     "test_out_of_bounds_write_to_tx_info_segment",
    //     calldata![],
    //     &mut state,
    // );

    run_security_test(
        "Validation failed: Read-only segments",
        "test_write_to_call_contract_return_value",
        calldata![],
        &mut state,
    );

    let calldata = calldata![stark_felt!(1), stark_felt!(1)];
    run_security_test(
        "Validation failed: Read-only segments",
        "test_out_of_bounds_write_to_calldata_segment",
        calldata,
        &mut state,
    );
}
