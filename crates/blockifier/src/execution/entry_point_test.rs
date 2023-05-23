use std::collections::HashSet;

use num_bigint::BigInt;
use pretty_assertions::assert_eq;
use starknet_api::core::{EntryPointSelector, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, patricia_key, stark_felt};

use crate::abi::abi_utils::{get_storage_var_address, selector_from_name};
use crate::execution::entry_point::{CallEntryPoint, CallExecution, CallInfo, Retdata};
use crate::execution::errors::EntryPointExecutionError;
use crate::retdata;
use crate::state::cached_state::CachedState;
use crate::test_utils::{
    create_test_state, deprecated_create_test_state, pad_address_to_64,
    trivial_external_entry_point, trivial_external_entry_point_security_test, DictStateReader,
    SECURITY_TEST_CONTRACT_ADDRESS, TEST_CONTRACT_ADDRESS, TEST_CONTRACT_ADDRESS_2,
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
        call: CallEntryPoint { calldata: calldata![stark_felt!(2_u8)], ..Default::default() },
        ..Default::default()
    };
    let right_leaf = CallInfo {
        call: CallEntryPoint { calldata: calldata![stark_felt!(3_u8)], ..Default::default() },
        ..Default::default()
    };
    let inner_node = CallInfo {
        call: CallEntryPoint { calldata: calldata![stark_felt!(1_u8)], ..Default::default() },
        inner_calls: vec![left_leaf],
        ..Default::default()
    };
    let root = CallInfo {
        call: CallEntryPoint { calldata: calldata![stark_felt!(0_u8)], ..Default::default() },
        inner_calls: vec![inner_node, right_leaf],
        ..Default::default()
    };

    for (i, call_info) in root.into_iter().enumerate() {
        assert_eq!(call_info.call.calldata, calldata![stark_felt!(i as u64)]);
    }
}

#[test]
fn test_entry_point_without_arg() {
    let mut state = deprecated_create_test_state();
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("without_arg"),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::default()
    );
}

#[test]
fn test_entry_point_with_arg() {
    let mut state = deprecated_create_test_state();
    let calldata = calldata![stark_felt!(25_u8)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("with_arg"),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::default()
    );
}

#[test]
fn test_long_retdata() {
    let mut state = deprecated_create_test_state();
    let calldata = calldata![];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_long_retdata"),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![
            stark_felt!(0_u8),
            stark_felt!(1_u8),
            stark_felt!(2_u8),
            stark_felt!(3_u8),
            stark_felt!(4_u8)
        ])
    );
}

#[test]
fn test_entry_point_with_builtin() {
    let mut state = deprecated_create_test_state();
    let calldata = calldata![stark_felt!(47_u8), stark_felt!(31_u8)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("bitwise_and"),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::default()
    );
}

#[test]
fn test_entry_point_with_hint() {
    let mut state = deprecated_create_test_state();
    let calldata = calldata![stark_felt!(81_u8)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("sqrt"),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::default()
    );
}

#[test]
fn test_entry_point_with_return_value() {
    let mut state = deprecated_create_test_state();
    let calldata = calldata![stark_felt!(23_u8)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("return_result"),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![stark_felt!(23_u8)])
    );
}

#[test]
fn test_entry_point_not_found_in_contract() {
    let mut state = deprecated_create_test_state();
    let entry_point_selector = EntryPointSelector(stark_felt!(2_u8));
    let entry_point_call =
        CallEntryPoint { entry_point_selector, ..trivial_external_entry_point() };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err();
    assert_eq!(
        format!("Entry point {entry_point_selector:?} not found in contract."),
        format!("{error}")
    );
}

#[test]
fn test_storage_var() {
    let mut state = deprecated_create_test_state();
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_storage_var"),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::default()
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
        ..trivial_external_entry_point_security_test()
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
    let mut state = deprecated_create_test_state();

    run_security_test(
        "Expected relocatable",
        "test_nonrelocatable_syscall_ptr",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Unknown value for memory cell",
        "test_unknown_memory",
        calldata![],
        &mut state,
    );

    run_security_test(
        "can't subtract two relocatable values with different segment indexes",
        "test_subtraction_between_relocatables",
        calldata![],
        &mut state,
    );

    run_security_test(
        "can't add two relocatable values",
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

    run_security_test(
        "Out of bounds access to program segment",
        "test_write_to_program_segment",
        calldata![],
        &mut state,
    );

    run_security_test("Cannot exit main scope.", "test_exit_main_scope", calldata![], &mut state);

    run_security_test(
        "Every enter_scope() requires a corresponding exit_scope()",
        "test_missing_exit_scope",
        calldata![],
        &mut state,
    );

    run_security_test(
        "maximum offset value exceeded",
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

    run_security_test(
        "Bad expr: {test}. (Cannot evaluate ap-based or complex references: ['test'])",
        "test_bad_expr_eval",
        calldata![],
        &mut state,
    );
}

#[test]
fn test_builtin_execution_security_failures() {
    let mut state = deprecated_create_test_state();

    run_security_test(
        "Inconsistent auto-deduction for builtin pedersen",
        "test_bad_pedersen_values",
        calldata![],
        &mut state,
    );

    let u128_bound: BigInt = BigInt::from(u128::MAX) + 1;
    let u123_bound_plus_one = u128_bound.clone() + 1;
    run_security_test(
        &format!(
            "Range-check validation failed, number {u123_bound_plus_one} is out of valid range \
             [0, {u128_bound}]"
        ),
        "test_bad_range_check_values",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Signature hint is missing",
        "test_missing_signature_hint",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Signature hint must point to the signature builtin segment",
        "test_signature_hint_on_wrong_segment",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Cannot apply EC operation: computation reached two points with the same x coordinate",
        "test_ec_op_invalid_input",
        calldata![],
        &mut state,
    );

    run_security_test(
        "is not on the curve",
        "test_ec_op_point_not_on_curve",
        calldata![],
        &mut state,
    );
}

#[test]
fn test_syscall_execution_security_failures() {
    let mut state = deprecated_create_test_state();

    for perform_inner_call_to_foo in 0..2 {
        let calldata = calldata![stark_felt!(perform_inner_call_to_foo as u8)];
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
        "Custom Hint Error: Expected relocatable",
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
    let mut state = deprecated_create_test_state();

    run_security_test(
        "Missing memory cells for builtin range_check",
        "test_builtin_hole",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Missing memory cells for builtin pedersen",
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

    run_security_test(
        "Validation failed: Read-only segments",
        "test_out_of_bounds_write_to_tx_info_segment",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Validation failed: Read-only segments",
        "test_write_to_call_contract_return_value",
        calldata![],
        &mut state,
    );

    let calldata = calldata![stark_felt!(1_u8), stark_felt!(1_u8)];
    run_security_test(
        "Validation failed: Read-only segments",
        "test_out_of_bounds_write_to_calldata_segment",
        calldata,
        &mut state,
    );
}

// Tests correct update of the fields: `storage_read_values` and `accessed_storage_keys`.
// Note read values also contain the reads performed right before a write operation.
#[test]
fn test_storage_related_members() {
    let mut state = deprecated_create_test_state();

    // Test storage variable.
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_storage_var"),
        ..trivial_external_entry_point()
    };
    let actual_call_info = entry_point_call.execute_directly(&mut state).unwrap();
    assert_eq!(actual_call_info.storage_read_values, vec![stark_felt!(0_u8), stark_felt!(39_u8)]);
    assert_eq!(
        actual_call_info.accessed_storage_keys,
        HashSet::from([get_storage_var_address("number_map", &[stark_felt!(1_u8)]).unwrap()])
    );

    // Test raw storage read and write.
    let key = stark_felt!(1234_u16);
    let value = stark_felt!(18_u8);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        ..trivial_external_entry_point()
    };
    let actual_call_info = entry_point_call.execute_directly(&mut state).unwrap();
    assert_eq!(actual_call_info.storage_read_values, vec![stark_felt!(0_u8), value]);
    assert_eq!(
        actual_call_info.accessed_storage_keys,
        HashSet::from([StorageKey(patricia_key!(key))])
    );
}

#[test]
fn test_cairo1_entry_point_segment_arena() {
    let mut state = create_test_state();
    let calldata = calldata![];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("segment_arena_builtin"),
        ..trivial_external_entry_point()
    };

    let res = entry_point_call.execute_directly(&mut state);
    assert!(res.is_ok());
}

#[test]
fn test_stack_trace() {
    let mut state = deprecated_create_test_state();
    // Nest 3 calls: test_call_contract -> test_call_contract -> assert_0_is_1.
    let outer_entry_point_selector = selector_from_name("test_call_contract");
    let inner_entry_point_selector = selector_from_name("foo");
    let calldata = calldata![
        stark_felt!(TEST_CONTRACT_ADDRESS_2), // Contract address.
        outer_entry_point_selector.0,         // Calling test_call_contract again.
        stark_felt!(3_u8),                    /* Calldata length for inner
                                               * test_call_contract. */
        stark_felt!(SECURITY_TEST_CONTRACT_ADDRESS), // Contract address.
        inner_entry_point_selector.0,                // Function selector.
        stark_felt!(0_u8)                            // Innermost calldata length.
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
