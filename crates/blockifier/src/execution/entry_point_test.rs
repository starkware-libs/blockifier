use std::collections::HashSet;

use cairo_vm::serde::deserialize_program::BuiltinName;
use num_bigint::BigInt;
use pretty_assertions::assert_eq;
use starknet_api::core::{ContractAddress, EntryPointSelector, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, contract_address, patricia_key, stark_felt};

use crate::abi::abi_utils::{get_storage_var_address, selector_from_name};
use crate::abi::constants;
use crate::block_context::ChainInfo;
use crate::execution::call_info::{CallExecution, CallInfo, Retdata};
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::errors::EntryPointExecutionError;
use crate::retdata;
use crate::state::cached_state::CachedState;
use crate::test_utils::cached_state::{create_test_state, deprecated_create_test_state};
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{
    create_calldata, pad_address_to_64, trivial_external_entry_point,
    trivial_external_entry_point_security_test, SECURITY_TEST_CONTRACT_ADDRESS,
    TEST_CONTRACT_ADDRESS, TEST_CONTRACT_ADDRESS_2,
};

const INNER_CALL_CONTRACT_IN_CALL_CHAIN_OFFSET: usize = 65;

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
        // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion
        // works.
        assert_eq!(
            call_info.call.calldata,
            calldata![stark_felt!(u64::try_from(i).expect("Failed to convert usize to u64."))]
        );
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
    state: &mut CachedState<DictStateReader>,
    security_contract: FeatureContract,
    expected_error: &str,
    entry_point_name: &str,
    calldata: Calldata,
) {
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name(entry_point_name),
        calldata,
        storage_address: security_contract.get_instance_address(0),
        initial_gas: constants::INITIAL_GAS_COST,
        ..Default::default()
    };
    let error = match entry_point_call.execute_directly(state) {
        Err(error) => error.to_string(),
        Ok(_) => panic!(
            "Entry point '{entry_point_name}' did not fail! Expected error: {expected_error}"
        ),
    };
    pretty_assertions::assert_eq!(error, expected_error);
    if !error.contains(expected_error) {
        panic!("Expected error: {expected_error}.\nGot: {error}")
    }
}

#[test]
fn test_vm_execution_security_failures() {
    let chain_info = ChainInfo::create_for_testing();
    let security_contract = FeatureContract::SecurityTests;
    let state = &mut test_state(&chain_info, BALANCE, &[(security_contract, 1)]);

    run_security_test(
        "Expected relocatable at address 1:11",
        "test_nonrelocatable_syscall_ptr",
        calldata![],
    );
    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:124:
Couldn't compute operand op1. Unknown value for memory cell 6:0
Cairo traceback (most recent call last):
Unknown location (pc=0:129)
",
        "test_unknown_memory",
        calldata![],
    );
    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:142:
Operation failed: 6:0 - 3:0, can't subtract two relocatable values with different segment indexes
Cairo traceback (most recent call last):
Unknown location (pc=0:149)
",
        "test_subtraction_between_relocatables",
        calldata![],
    );
    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:162:
Operation failed: 6:0 + 6:0, can't add two relocatable values
Cairo traceback (most recent call last):
Unknown location (pc=0:167)
",
        "test_relocatables_addition_failure",
        calldata![],
    );
    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:180:
op0 must be known in double dereference
Cairo traceback (most recent call last):
Unknown location (pc=0:185)
",
        "test_op0_unknown_double_dereference",
        calldata![],
    );
    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Out of bounds access to program segment",
        "test_write_to_program_segment",
        calldata![],
    );

    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:218:
Got an exception while executing a hint: Cannot exit main scope.
Cairo traceback (most recent call last):
Unknown location (pc=0:220)
",
        "test_exit_main_scope",
        calldata![],
        &mut state,
    );

    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Every enter_scope() requires a corresponding exit_scope().",
        "test_missing_exit_scope",
        calldata![],
    );
    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:250:
Operation failed: 10:0 + \
         3618502788666131213697322783095070105623107215331596699973092056135872020480, maximum \
         offset value exceeded
Cairo traceback (most recent call last):
Unknown location (pc=0:254)
",
        "test_out_of_bound_memory_value",
        calldata![],
    );
    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:271:
Memory addresses must be relocatable
Cairo traceback (most recent call last):
Unknown location (pc=0:274)
",
        "test_non_relocatable_memory_address",
        calldata![],
    );
    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:289:
Error message: Bad expr: {test}. (Cannot evaluate ap-based or complex references: ['test'])

Cairo traceback (most recent call last):
Unknown location (pc=0:293)
",
        "test_bad_expr_eval",
        calldata![],
    );
}

#[test]
fn test_builtin_execution_security_failures() {
    let chain_info = ChainInfo::create_for_testing();
    let security_contract = FeatureContract::SecurityTests;
    let state = &mut test_state(&chain_info, BALANCE, &[(security_contract, 1)]);

    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Inconsistent auto-deduction for builtin pedersen_builtin, expected \
         2089986280348253421170679821480865132823066470938446095505822317253594081284, got \
         Some(Int(0))",
        "test_bad_pedersen_values",
        calldata![],
    );
    let u128_bound: BigInt = BigInt::from(u128::MAX) + 1;
    let u128_bound_plus_one = u128_bound.clone() + 1;
    run_security_test(
        state,
        security_contract,
        &format!(
            "Error in the called contract \
             (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:337:
Range-check validation failed, number {u128_bound_plus_one} is out of valid range [0, {u128_bound}]
Cairo traceback (most recent call last):
Unknown location (pc=0:345)
"
        ),
        "test_bad_range_check_values",
        calldata![],
    );
    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:363:
Signature hint is missing for ECDSA builtin at address 4:0.
    Add it using 'ecdsa_builtin.add_signature'.
Cairo traceback (most recent call last):
Unknown location (pc=0:370)
",
        "test_missing_signature_hint",
        calldata![],
    );
    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:51:
Got an exception while executing a hint: Signature hint must point to the signature builtin \
         segment, not 10:0.
Cairo traceback (most recent call last):
Unknown location (pc=0:401)
Unknown location (pc=0:393)
",
        "test_signature_hint_on_wrong_segment",
        calldata![],
    );
    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Cannot apply EC operation: computation reached two points with the same x coordinate.

    Attempting to compute P + m * Q where:

    P = (3004956058830981475544150447242655232275382685012344776588097793621230049020, \
         3232266734070744637901977159303149980795588196503166389060831401046564401743)

    m = 8

    Q = (3004956058830981475544150447242655232275382685012344776588097793621230049020, \
         3232266734070744637901977159303149980795588196503166389060831401046564401743).",
        "test_ec_op_invalid_input",
        calldata![],
    );
    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
EcOpBuiltin: point (2864041794633455918387139831609347757720597354645583729611044800117714995244, \
         2252415379535459416893084165764951913426528160630388985542241241048300343257) is not on \
         the curve",
        "test_ec_op_point_not_on_curve",
        calldata![],
    );
}

#[test]
fn test_syscall_execution_security_failures() {
    let chain_info = ChainInfo::create_for_testing();
    let security_contract = FeatureContract::SecurityTests;
    let state = &mut test_state(&chain_info, BALANCE, &[(security_contract, 1)]);

    for perform_inner_call_to_foo in 0..2 {
        // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion
        // works.
        let calldata = calldata![stark_felt!(
            u8::try_from(perform_inner_call_to_foo).expect("Failed to convert i32 to u8.")
        )];
        run_security_test(
            "Error in the called contract \
             (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:40:
Got an exception while executing a hint: Hint Error: Out of range [0x0, \
             0x800000000000000000000000000000000000000000000000000000000000000).
Cairo traceback (most recent call last):
Unknown location (pc=0:540)
Unknown location (pc=0:526)
",
            "test_read_bad_address",
            calldata.clone(),
        );

        run_security_test(
            "Error in the called contract \
             (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:40:
Got an exception while executing a hint: Hint Error: Expected integer at address 6:1
Cairo traceback (most recent call last):
Unknown location (pc=0:569)
Unknown location (pc=0:555)
",
            "test_relocatable_storage_address",
            calldata,
        );
    }

    run_security_test(
        r#"Error in the called contract (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:16:
Got an exception while executing a hint: Hint Error: Requested contract address ContractAddress(PatriciaKey(StarkFelt("0x0000000000000000000000000000000000000000000000000000000000000017"))) is not deployed.
Cairo traceback (most recent call last):
Unknown location (pc=0:598)
Unknown location (pc=0:592)
"#,
        "test_bad_call_address",
        calldata![],
    );
    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:626:
Got an exception while executing a hint: Hint Error: Expected relocatable at address 6:4
Cairo traceback (most recent call last):
Unknown location (pc=0:630)
",
        "test_bad_syscall_request_arg_type",
        calldata![],
    );
    run_security_test(
        r#"Error in the called contract (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:16:
Got an exception while executing a hint: Hint Error: Entry point EntryPointSelector(StarkFelt("0x0000000000000000000000000000000000000000000000000000000000000019")) not found in contract.
Cairo traceback (most recent call last):
Unknown location (pc=0:661)
Unknown location (pc=0:655)
"#,
        "test_bad_call_selector",
        calldata![],
    );
    run_security_test(
        r#"Error in the called contract (0x0000000000000000000000000000000000000000000000000000000000000300):
Error at pc=0:692:
Got an exception while executing a hint: Hint Error: Invalid syscall input: StarkFelt("0x0000000000000000000000000000000000000000000000000000000000000002"); The deploy_from_zero field in the deploy system call must be 0 or 1.
Cairo traceback (most recent call last):
Unknown location (pc=0:696)
"#,
        "test_bad_deploy_from_zero_field",
        calldata![],
    );
}

#[test]
fn test_post_run_validation_security_failure() {
    let chain_info = ChainInfo::create_for_testing();
    let security_contract = FeatureContract::SecurityTests;
    let state = &mut test_state(&chain_info, BALANCE, &[(security_contract, 1)]);

    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Missing memory cells for builtin range_check_builtin",
        "test_builtin_hole",
        calldata![],
    );
    run_security_test(
        "Error in the called contract \
         (0x0000000000000000000000000000000000000000000000000000000000000300):
Missing memory cells for builtin pedersen_builtin",
        "test_missing_pedersen_values",
        calldata![],
    );
    run_security_test(
        "Validation failed: Invalid stop pointer for range_check_builtin. Expected: 3:0, found: \
         3:2.",
        "test_bad_builtin_stop_ptr",
        calldata![],
    );
    run_security_test(
        "Validation failed: Syscall segment size.",
        "test_access_after_syscall_stop_ptr",
        calldata![],
    );
    run_security_test(
        "Validation failed: Syscall segment end.",
        "test_bad_syscall_stop_ptr",
        calldata![],
    );
    run_security_test(
        "Validation failed: Read-only segments.",
        "test_out_of_bounds_write_to_signature_segment",
        calldata![],
    );
    run_security_test(
        "Validation failed: Read-only segments.",
        "test_out_of_bounds_write_to_tx_info_segment",
        calldata![],
    );
    run_security_test(
        "Validation failed: Read-only segments.",
        "test_write_to_call_contract_return_value",
        calldata![],
    );
    let calldata = calldata![stark_felt!(1_u8), stark_felt!(1_u8)];
    run_security_test(
        "Validation failed: Read-only segments.",
        "test_out_of_bounds_write_to_calldata_segment",
        calldata,
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
        HashSet::from([get_storage_var_address("number_map", &[stark_felt!(1_u8)])])
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

    assert!(entry_point_call
        .execute_directly(&mut state)
        .unwrap()
        .vm_resources
        .builtin_instance_counter
        .contains_key(BuiltinName::segment_arena.name()));
}

#[test]
fn test_stack_trace() {
    let mut state = deprecated_create_test_state();
    // Nest 3 calls: test_call_contract -> test_call_contract -> assert_0_is_1.
    let call_contract_function_name = "test_call_contract";
    let inner_entry_point_selector = selector_from_name("foo");
    let calldata = create_calldata(
        contract_address!(TEST_CONTRACT_ADDRESS_2),
        call_contract_function_name,
        &[
            stark_felt!(SECURITY_TEST_CONTRACT_ADDRESS), // Contract address.
            inner_entry_point_selector.0,                // Function selector.
            stark_felt!(0_u8),                           // Innermost calldata length.
        ],
    );
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name(call_contract_function_name),
        calldata,
        ..trivial_external_entry_point()
    };

    let first = pad_address_to_64(TEST_CONTRACT_ADDRESS);
    let second = pad_address_to_64(TEST_CONTRACT_ADDRESS_2);
    let third = pad_address_to_64(SECURITY_TEST_CONTRACT_ADDRESS);
    let expected_trace = format!(
        "Error in the called contract ({first}):
Error at pc=0:34:
Got an exception while executing a hint: Hint Error: Error in the called contract ({second}):
Error at pc=0:34:
Got an exception while executing a hint: Hint Error: Error in the called contract ({third}):
Error at pc=0:58:
An ASSERT_EQ instruction failed: 1 != 0.
Cairo traceback (most recent call last):
Unknown location (pc=0:62)

Cairo traceback (most recent call last):
Unknown location (pc=0:741)
Unknown location (pc=0:724)

Error in the called contract ({third}):
Error at pc=0:58:
An ASSERT_EQ instruction failed: 1 != 0.
Cairo traceback (most recent call last):
Unknown location (pc=0:62)

Cairo traceback (most recent call last):
Unknown location (pc=0:741)
Unknown location (pc=0:724)

Error in the called contract ({second}):
Error at pc=0:34:
Got an exception while executing a hint: Hint Error: Error in the called contract ({third}):
Error at pc=0:58:
An ASSERT_EQ instruction failed: 1 != 0.
Cairo traceback (most recent call last):
Unknown location (pc=0:62)

Cairo traceback (most recent call last):
Unknown location (pc=0:741)
Unknown location (pc=0:724)

Error in the called contract ({third}):
Error at pc=0:58:
An ASSERT_EQ instruction failed: 1 != 0.
Cairo traceback (most recent call last):
Unknown location (pc=0:62)
"
    );

    let pc_location = entry_point_offset.0 + 82;
    let expected_trace_cairo1 = format!(
        "Error in the called contract ({}):
Error at pc=0:4942:
Got an exception while executing a hint.
Cairo traceback (most recent call last):
Unknown location (pc=0:{pc_location})

Error in the called contract ({}):
Error at pc=0:4942:
Got an exception while executing a hint: Hint Error: Execution failed. Failure reason: 0x6661696c \
         ('fail').
Cairo traceback (most recent call last):
Unknown location (pc=0:{pc_location})

Error in the called contract ({}):
Execution failed. Failure reason: 0x6661696c ('fail').
",
        *test_contract_address.0.key(),
        *test_contract_address_2.0.key(),
        *test_contract_address_3.0.key(),
    );

    let expected_trace = match cairo_version {
        CairoVersion::Cairo0 => expected_trace_cairo0,
        CairoVersion::Cairo1 => expected_trace_cairo1,
    };

    match entry_point_call.execute_directly(&mut state).unwrap_err() {
        EntryPointExecutionError::VirtualMachineExecutionErrorWithTrace { trace, source: _ } => {
            dbg!(&trace);
            assert_eq!(trace, expected_trace)
        }
        other_error => panic!("Unexpected error type: {other_error:?}"),
    }
}

#[rstest]
#[case("invoke_call_chain", "0x75382069732030 ('u8 is 0')")]
#[case("fail", "0x6661696c ('fail')")]
fn test_trace_callchain_ends_with_regular_call(
    #[case] last_func_name: &str,
    #[case] expected_error: &str,
) {
    let chain_info = ChainInfo::create_for_testing();
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let mut state = test_state(&chain_info, BALANCE, &[(test_contract, 1)]);
    let test_contract_address = test_contract.get_instance_address(0);
    let contract_address_felt = *test_contract_address.0.key();

    // invoke_call_chain -> call_contract_syscall invoke_call_chain -> regular call to final func.
    let invoke_call_chain_selector = selector_from_name("invoke_call_chain");

    let calldata = calldata![
        stark_felt!(7_u8),                    // Calldata length
        contract_address_felt,                // Contract address.
        invoke_call_chain_selector.0,         // Function selector.
        stark_felt!(0_u8),                    // Call type: call_contract_syscall.
        stark_felt!(3_u8),                    // Calldata length
        contract_address_felt,                // Contract address.
        selector_from_name(last_func_name).0, // Function selector.
        stark_felt!(2_u8)                     // Call type: regular call.
    ];

    let entry_point_call = CallEntryPoint {
        entry_point_selector: invoke_call_chain_selector,
        calldata,
        ..trivial_external_entry_point_with_address(test_contract_address)
    };

    let entry_point_offset =
        get_entry_point_offset(&test_contract.get_class(), entry_point_call.entry_point_selector);
    let pc_location = entry_point_offset.0 + INNER_CALL_CONTRACT_IN_CALL_CHAIN_OFFSET;

    let expected_trace = format!(
        "Error in the called contract ({contract_address_felt}):
Error at pc=0:7981:
Got an exception while executing a hint: Hint Error: Execution failed. Failure reason: \
         {expected_error}.
Cairo traceback (most recent call last):
Unknown location (pc=0:{pc_location})

Error in the called contract ({contract_address_felt}):
Execution failed. Failure reason: {expected_error}.
"
    );

    let actual_trace = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert_eq!(actual_trace, expected_trace);
}

#[rstest]
#[case("invoke_call_chain", "0x75382069732030 ('u8 is 0')", 1_u8)]
#[case("fail", "0x6661696c ('fail')", 0_u8)]
fn test_trace_call_chain_with_syscalls(
    #[values((0_u8, 7981_u16), (1_u8, 8070_u16))] call_type_expected_pc: (u8, u16),
    #[case] last_func_name: &str,
    #[case] expected_error: &str,
    #[case] calldata_extra_length: u8,
) {
    let (call_type, expected_pc) = call_type_expected_pc;
    let chain_info = ChainInfo::create_for_testing();
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let mut state = test_state(&chain_info, BALANCE, &[(test_contract, 1)]);
    let test_contract_address = test_contract.get_instance_address(0);
    let test_contract_hash = test_contract.get_class_hash().0;
    let address_felt = *test_contract_address.0.key();
    let contract_id = if call_type == 0 { address_felt } else { test_contract_hash };

    // invoke_call_chain -> call_contract_syscall invoke_call_chain -> call_contract_syscall /
    // library_call_syscall to final func.
    let invoke_call_chain_selector = selector_from_name("invoke_call_chain");

    let mut calldata = vec![
        stark_felt!(7_u8 + calldata_extra_length), // Calldata length
        address_felt,                              // Contract address.
        invoke_call_chain_selector.0,              // Function selector.
        stark_felt!(0_u8),                         // Call type: call_contract_syscall.
        stark_felt!(3_u8 + calldata_extra_length), // Calldata length
        contract_id,                               // Contract address / class hash.
        selector_from_name(last_func_name).0,      // Function selector.
        stark_felt!(call_type),                    // Syscall type: library_call or call_contract.
    ];

    // Need to send an empty array for the last call in `invoke_call_chain` variant.
    if last_func_name == "invoke_call_chain" {
        calldata.push(stark_felt!(0_u8));
    }

    let entry_point_call = CallEntryPoint {
        entry_point_selector: invoke_call_chain_selector,
        calldata: Calldata(calldata.into()),
        ..trivial_external_entry_point_with_address(test_contract_address)
    };

    let entry_point_offset =
        get_entry_point_offset(&test_contract.get_class(), entry_point_call.entry_point_selector);
    let pc_location = entry_point_offset.0 + INNER_CALL_CONTRACT_IN_CALL_CHAIN_OFFSET;

    let expected_trace = format!(
        "Error in the called contract ({address_felt}):
Error at pc=0:7981:
Got an exception while executing a hint.
Cairo traceback (most recent call last):
Unknown location (pc=0:{pc_location})

Error in the called contract ({address_felt}):
Error at pc=0:{expected_pc}:
Got an exception while executing a hint: Hint Error: Execution failed. Failure reason: \
         {expected_error}.
Cairo traceback (most recent call last):
Unknown location (pc=0:{pc_location})

Error in the called contract ({address_felt}):
Execution failed. Failure reason: {expected_error}.
"
    );

    let actual_trace = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert_eq!(actual_trace, expected_trace);
}
