use std::collections::HashSet;

use cairo_vm::serde::deserialize_program::BuiltinName;
use num_bigint::BigInt;
use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::core::{EntryPointSelector, PatriciaKey};
use starknet_api::deprecated_contract_class::{EntryPointOffset, EntryPointType};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, patricia_key, stark_felt};

use crate::abi::abi_utils::{get_storage_var_address, selector_from_name};
use crate::context::ChainInfo;
use crate::execution::call_info::{CallExecution, CallInfo, Retdata};
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::errors::EntryPointExecutionError;
use crate::retdata;
use crate::state::cached_state::CachedState;
use crate::test_utils::cached_state::deprecated_create_test_state;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{
    create_calldata, trivial_external_entry_point, trivial_external_entry_point_new,
    trivial_external_entry_point_with_address, CairoVersion, BALANCE,
};
use crate::versioned_constants::VersionedConstants;

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
    let versioned_constants = VersionedConstants::create_for_testing();
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name(entry_point_name),
        calldata,
        storage_address: security_contract.get_instance_address(0),
        initial_gas: versioned_constants.gas_cost("initial_gas_cost"),
        ..Default::default()
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
    let chain_info = ChainInfo::create_for_testing();
    let security_contract = FeatureContract::SecurityTests;
    let state = &mut test_state(&chain_info, BALANCE, &[(security_contract, 1)]);

    run_security_test(
        state,
        security_contract,
        "Expected relocatable",
        "test_nonrelocatable_syscall_ptr",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Unknown value for memory cell",
        "test_unknown_memory",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "can't subtract two relocatable values with different segment indexes",
        "test_subtraction_between_relocatables",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "can't add two relocatable values",
        "test_relocatables_addition_failure",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "op0 must be known in double dereference",
        "test_op0_unknown_double_dereference",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Out of bounds access to program segment",
        "test_write_to_program_segment",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Cannot exit main scope.",
        "test_exit_main_scope",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Every enter_scope() requires a corresponding exit_scope()",
        "test_missing_exit_scope",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "maximum offset value exceeded",
        "test_out_of_bound_memory_value",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Memory addresses must be relocatable",
        "test_non_relocatable_memory_address",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Bad expr: {test}. (Cannot evaluate ap-based or complex references: ['test'])",
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
        state,
        security_contract,
        "Inconsistent auto-deduction for builtin pedersen",
        "test_bad_pedersen_values",
        calldata![],
    );
    let u128_bound: BigInt = BigInt::from(u128::MAX) + 1;
    let u123_bound_plus_one = u128_bound.clone() + 1;
    run_security_test(
        state,
        security_contract,
        &format!(
            "Range-check validation failed, number {u123_bound_plus_one} is out of valid range \
             [0, {u128_bound}]"
        ),
        "test_bad_range_check_values",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Signature hint is missing",
        "test_missing_signature_hint",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Signature hint must point to the signature builtin segment",
        "test_signature_hint_on_wrong_segment",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Cannot apply EC operation: computation reached two points with the same x coordinate",
        "test_ec_op_invalid_input",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "is not on the curve",
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
            state,
            security_contract,
            "Out of range",
            "test_read_bad_address",
            calldata.clone(),
        );

        run_security_test(
            state,
            security_contract,
            "Expected integer",
            "test_relocatable_storage_address",
            calldata,
        );
    }

    run_security_test(
        state,
        security_contract,
        "Requested contract address \
         ContractAddress(PatriciaKey(StarkFelt(\"\
         0x0000000000000000000000000000000000000000000000000000000000000017\"))) is not deployed",
        "test_bad_call_address",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Expected relocatable",
        "test_bad_syscall_request_arg_type",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Entry point \
         EntryPointSelector(StarkFelt(\"\
         0x0000000000000000000000000000000000000000000000000000000000000019\")) not found in \
         contract",
        "test_bad_call_selector",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "The deploy_from_zero field in the deploy system call must be 0 or 1.",
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
        state,
        security_contract,
        "Missing memory cells for builtin range_check",
        "test_builtin_hole",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Missing memory cells for builtin pedersen",
        "test_missing_pedersen_values",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Validation failed: Invalid stop pointer for range_check",
        "test_bad_builtin_stop_ptr",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Validation failed: Syscall segment size",
        "test_access_after_syscall_stop_ptr",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Validation failed: Syscall segment end",
        "test_bad_syscall_stop_ptr",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Validation failed: Read-only segments",
        "test_out_of_bounds_write_to_signature_segment",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Validation failed: Read-only segments",
        "test_out_of_bounds_write_to_tx_info_segment",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Validation failed: Read-only segments",
        "test_write_to_call_contract_return_value",
        calldata![],
    );
    let calldata = calldata![stark_felt!(1_u8), stark_felt!(1_u8)];
    run_security_test(
        state,
        security_contract,
        "Validation failed: Read-only segments",
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
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);
    let calldata = calldata![];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("segment_arena_builtin"),
        ..trivial_external_entry_point_new(test_contract)
    };

    assert!(
        entry_point_call
            .execute_directly(&mut state)
            .unwrap()
            .resources
            .builtin_instance_counter
            .contains_key(BuiltinName::segment_arena.name())
    );
}

/// Fetch PC locations from the compiled contract to compute the expected PC locations in the
/// traceback. Computation is not robust, but as long as the cairo function itself is not edited,
/// this computation should be stable.
fn get_entry_point_offset(
    contract_class: &ContractClass,
    entry_point_selector: EntryPointSelector,
) -> EntryPointOffset {
    match contract_class {
        ContractClass::V0(class) => {
            class
                .entry_points_by_type
                .get(&EntryPointType::External)
                .unwrap()
                .iter()
                .find(|ep| ep.selector == entry_point_selector)
                .unwrap()
                .offset
        }
        ContractClass::V1(_) => panic!("Expected contract class V0, got V1."),
        ContractClass::V1Sierra(_) => panic!("Expected contract class V0, got V1Sierra."),
    }
}

#[rstest]
fn test_stack_trace(
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let chain_info = ChainInfo::create_for_testing();
    let test_contract = FeatureContract::TestContract(cairo_version);
    let mut state = test_state(&chain_info, BALANCE, &[(test_contract, 3)]);
    let test_contract_address = test_contract.get_instance_address(0);
    let test_contract_address_2 = test_contract.get_instance_address(1);
    let test_contract_address_3 = test_contract.get_instance_address(2);

    // Nest 3 calls: test_call_contract -> test_call_contract -> assert_0_is_1.
    let call_contract_function_name = "test_call_contract";
    let inner_entry_point_selector = selector_from_name("fail");
    let calldata = create_calldata(
        test_contract_address_2, // contract_address
        call_contract_function_name,
        &[
            *test_contract_address_3.0.key(), // Contract address.
            inner_entry_point_selector.0,     // Function selector.
            stark_felt!(0_u8),                // Innermost calldata length.
        ],
    );
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name(call_contract_function_name),
        calldata,
        ..trivial_external_entry_point_with_address(test_contract_address)
    };

    // Fetch PC locations from the compiled contract to compute the expected PC locations in the
    // traceback. Computation is not robust, but as long as the cairo function itself is not edited,
    // this computation should be stable.
    let contract_class = test_contract.get_class();
    let entry_point_offset =
        get_entry_point_offset(&contract_class, entry_point_call.entry_point_selector);
    // Relative offsets of the test_call_contract entry point and the inner call.
    let call_location = entry_point_offset.0 + 14;
    let entry_point_location = entry_point_offset.0 - 3;

    let expected_trace_cairo0 = format!(
        "Error in the called contract ({}):
Error at pc=0:37:
Got an exception while executing a hint.
Cairo traceback (most recent call last):
Unknown location (pc=0:{call_location})
Unknown location (pc=0:{entry_point_location})

Error in the called contract ({}):
Error at pc=0:37:
Got an exception while executing a hint.
Cairo traceback (most recent call last):
Unknown location (pc=0:{call_location})
Unknown location (pc=0:{entry_point_location})

Error in the called contract ({}):
Error at pc=0:1184:
An ASSERT_EQ instruction failed: 1 != 0.
Cairo traceback (most recent call last):
Unknown location (pc=0:1188)
",
        *test_contract_address.0.key(),
        *test_contract_address_2.0.key(),
        *test_contract_address_3.0.key(),
    );

    let pc_location = entry_point_offset.0 + 82;
    let expected_trace_cairo1 = format!(
        "Error in the called contract ({}):
Error at pc=0:4992:
Got an exception while executing a hint.
Cairo traceback (most recent call last):
Unknown location (pc=0:{pc_location})

Error in the called contract ({}):
Error at pc=0:4992:
Got an exception while executing a hint: Execution failed. Failure reason: 0x6661696c ('fail').
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
            assert_eq!(trace, expected_trace)
        }
        other_error => panic!("Unexpected error type: {other_error:?}"),
    }
}

#[rstest]
#[case(CairoVersion::Cairo0, "invoke_call_chain", "Couldn't compute operand op0. Unknown value for memory cell 1:37", (1081_u16, 1127_u16))]
#[case(CairoVersion::Cairo0, "fail", "An ASSERT_EQ instruction failed: 1 != 0.", (1184_u16, 1135_u16))]
#[case(CairoVersion::Cairo1, "invoke_call_chain", "0x75382069732030 ('u8 is 0')", (0_u16, 0_u16))]
#[case(CairoVersion::Cairo1, "fail", "0x6661696c ('fail')", (0_u16, 0_u16))]
fn test_trace_callchain_ends_with_regular_call(
    #[case] cairo_version: CairoVersion,
    #[case] last_func_name: &str,
    #[case] expected_error: &str,
    #[case] expected_pc_locations: (u16, u16),
) {
    let chain_info = ChainInfo::create_for_testing();
    let test_contract = FeatureContract::TestContract(cairo_version);
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

    let expected_trace = match cairo_version {
        CairoVersion::Cairo0 => {
            let call_location = entry_point_offset.0 + 12;
            let entry_point_location = entry_point_offset.0 - 61;
            format!(
                "Error in the called contract ({contract_address_felt}):
Error at pc=0:37:
Got an exception while executing a hint.
Cairo traceback (most recent call last):
Unknown location (pc=0:{call_location})
Unknown location (pc=0:{entry_point_location})

Error in the called contract ({contract_address_felt}):
Error at pc=0:{}:
{expected_error}
Cairo traceback (most recent call last):
Unknown location (pc=0:{call_location})
Unknown location (pc=0:{})
",
                expected_pc_locations.0, expected_pc_locations.1
            )
        }
        CairoVersion::Cairo1 => {
            let pc_location = entry_point_offset.0 + INNER_CALL_CONTRACT_IN_CALL_CHAIN_OFFSET;
            format!(
                "Error in the called contract ({contract_address_felt}):
Error at pc=0:8010:
Got an exception while executing a hint: Execution failed. Failure reason: {expected_error}.
Cairo traceback (most recent call last):
Unknown location (pc=0:{pc_location})

Error in the called contract ({contract_address_felt}):
Execution failed. Failure reason: {expected_error}.
"
            )
        }
    };

    let actual_trace = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert_eq!(actual_trace, expected_trace);
}

#[rstest]
#[case(CairoVersion::Cairo0, "invoke_call_chain", "Couldn't compute operand op0. Unknown value for memory cell 1:23", 1_u8, 0_u8, (37_u16, 1093_u16, 1081_u16, 1166_u16))]
#[case(CairoVersion::Cairo0, "invoke_call_chain", "Couldn't compute operand op0. Unknown value for memory cell 1:23", 1_u8, 1_u8, (49_u16, 1111_u16, 1081_u16, 1166_u16))]
#[case(CairoVersion::Cairo0, "fail", "An ASSERT_EQ instruction failed: 1 != 0.", 0_u8, 0_u8, (37_u16, 1093_u16, 1184_u16, 1188_u16))]
#[case(CairoVersion::Cairo0, "fail", "An ASSERT_EQ instruction failed: 1 != 0.", 0_u8, 1_u8, (49_u16, 1111_u16, 1184_u16, 1188_u16))]
#[case(CairoVersion::Cairo1, "invoke_call_chain", "0x75382069732030 ('u8 is 0')", 1_u8, 0_u8, (8010_u16, 0_u16, 0_u16, 0_u16))]
#[case(CairoVersion::Cairo1, "invoke_call_chain", "0x75382069732030 ('u8 is 0')", 1_u8, 1_u8, (8099_u16, 0_u16, 0_u16, 0_u16))]
#[case(CairoVersion::Cairo1, "fail", "0x6661696c ('fail')", 0_u8, 0_u8, (8010_u16, 0_u16, 0_u16, 0_u16))]
#[case(CairoVersion::Cairo1, "fail", "0x6661696c ('fail')", 0_u8, 1_u8, (8099_u16, 0_u16, 0_u16, 0_u16))]
fn test_trace_call_chain_with_syscalls(
    #[case] cairo_version: CairoVersion,
    #[case] last_func_name: &str,
    #[case] expected_error: &str,
    #[case] calldata_extra_length: u8,
    #[case] call_type: u8,
    #[case] expected_pcs: (u16, u16, u16, u16),
) {
    let chain_info = ChainInfo::create_for_testing();
    let test_contract = FeatureContract::TestContract(cairo_version);
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

    let expected_trace = match cairo_version {
        CairoVersion::Cairo0 => {
            let call_location = entry_point_offset.0 + 12;
            let entry_point_location = entry_point_offset.0 - 61;
            format!(
                "Error in the called contract ({address_felt}):
Error at pc=0:37:
Got an exception while executing a hint.
Cairo traceback (most recent call last):
Unknown location (pc=0:{call_location})
Unknown location (pc=0:{entry_point_location})

Error in the called contract ({address_felt}):
Error at pc=0:{}:
Got an exception while executing a hint.
Cairo traceback (most recent call last):
Unknown location (pc=0:{call_location})
Unknown location (pc=0:{})

Error in the called contract ({address_felt}):
Error at pc=0:{}:
{expected_error}
Cairo traceback (most recent call last):
Unknown location (pc=0:{})
",
                expected_pcs.0, expected_pcs.1, expected_pcs.2, expected_pcs.3
            )
        }
        CairoVersion::Cairo1 => {
            let pc_location = entry_point_offset.0 + INNER_CALL_CONTRACT_IN_CALL_CHAIN_OFFSET;
            format!(
                "Error in the called contract ({address_felt}):
Error at pc=0:8010:
Got an exception while executing a hint.
Cairo traceback (most recent call last):
Unknown location (pc=0:{pc_location})

Error in the called contract ({address_felt}):
Error at pc=0:{}:
Got an exception while executing a hint: Execution failed. Failure reason: {expected_error}.
Cairo traceback (most recent call last):
Unknown location (pc=0:{pc_location})

Error in the called contract ({address_felt}):
Execution failed. Failure reason: {expected_error}.
",
                expected_pcs.0
            )
        }
    };

    let actual_trace = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert_eq!(actual_trace, expected_trace);
}
