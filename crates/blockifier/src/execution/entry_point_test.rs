use std::collections::HashSet;

use cairo_vm::types::builtin_name::BuiltinName;
use num_bigint::BigInt;
use pretty_assertions::assert_eq;
use starknet_api::core::{EntryPointSelector, PatriciaKey};
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, felt};

use crate::abi::abi_utils::{get_storage_var_address, selector_from_name};
use crate::context::ChainInfo;
use crate::execution::call_info::{CallExecution, CallInfo, Retdata};
use crate::execution::entry_point::CallEntryPoint;
use crate::state::cached_state::CachedState;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{trivial_external_entry_point_new, CairoVersion, BALANCE};
use crate::versioned_constants::VersionedConstants;
use crate::{retdata, storage_key};

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
        call: CallEntryPoint { calldata: calldata![felt!(2_u8)], ..Default::default() },
        ..Default::default()
    };
    let right_leaf = CallInfo {
        call: CallEntryPoint { calldata: calldata![felt!(3_u8)], ..Default::default() },
        ..Default::default()
    };
    let inner_node = CallInfo {
        call: CallEntryPoint { calldata: calldata![felt!(1_u8)], ..Default::default() },
        inner_calls: vec![left_leaf],
        ..Default::default()
    };
    let root = CallInfo {
        call: CallEntryPoint { calldata: calldata![felt!(0_u8)], ..Default::default() },
        inner_calls: vec![inner_node, right_leaf],
        ..Default::default()
    };

    for (i, call_info) in root.iter().enumerate() {
        // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion
        // works.
        assert_eq!(
            call_info.call.calldata,
            calldata![felt!(u64::try_from(i).expect("Failed to convert usize to u64."))]
        );
    }
}

#[test]
fn test_entry_point_without_arg() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("without_arg"),
        ..trivial_external_entry_point_new(test_contract)
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::default()
    );
}

#[test]
fn test_entry_point_with_arg() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let calldata = calldata![felt!(25_u8)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("with_arg"),
        ..trivial_external_entry_point_new(test_contract)
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::default()
    );
}

#[test]
fn test_long_retdata() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let calldata = calldata![];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_long_retdata"),
        ..trivial_external_entry_point_new(test_contract)
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![
            felt!(0_u8),
            felt!(1_u8),
            felt!(2_u8),
            felt!(3_u8),
            felt!(4_u8)
        ])
    );
}

#[test]
fn test_entry_point_with_builtin() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let calldata = calldata![felt!(47_u8), felt!(31_u8)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("bitwise_and"),
        ..trivial_external_entry_point_new(test_contract)
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::default()
    );
}

#[test]
fn test_entry_point_with_hint() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let calldata = calldata![felt!(81_u8)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("sqrt"),
        ..trivial_external_entry_point_new(test_contract)
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::default()
    );
}

#[test]
fn test_entry_point_with_return_value() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let calldata = calldata![felt!(23_u8)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("return_result"),
        ..trivial_external_entry_point_new(test_contract)
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![felt!(23_u8)])
    );
}

#[test]
fn test_entry_point_not_found_in_contract() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let entry_point_selector = EntryPointSelector(felt!(2_u8));
    let entry_point_call =
        CallEntryPoint { entry_point_selector, ..trivial_external_entry_point_new(test_contract) };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err();
    assert_eq!(
        format!("Entry point {entry_point_selector:?} not found in contract."),
        format!("{error}")
    );
}

#[test]
fn test_storage_var() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_storage_var"),
        ..trivial_external_entry_point_new(test_contract)
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
        initial_gas: versioned_constants.os_constants.gas_costs.initial_gas_cost,
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
        "Inconsistent auto-deduction for pedersen_builtin",
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
        let calldata = calldata![felt!(
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
         0x0000000000000000000000000000000000000000000000000000000000000017 is not deployed",
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
        "Entry point EntryPointSelector(0x19) not found in contract",
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
        "Missing memory cells for range_check_builtin",
        "test_builtin_hole",
        calldata![],
    );
    run_security_test(
        state,
        security_contract,
        "Missing memory cells for pedersen_builtin",
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
    let calldata = calldata![felt!(1_u8), felt!(1_u8)];
    run_security_test(
        state,
        security_contract,
        "Validation failed: Read-only segments",
        "test_out_of_bounds_write_to_calldata_segment",
        calldata,
    );
}

// Tests correct update of the fields: `storage_read_values` and `accessed_storage_keys`.
#[test]
fn test_storage_related_members() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);

    // Test storage variable.
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_storage_var"),
        ..trivial_external_entry_point_new(test_contract)
    };
    let actual_call_info = entry_point_call.execute_directly(&mut state).unwrap();
    assert_eq!(actual_call_info.storage_read_values, vec![felt!(39_u8)]);
    assert_eq!(
        actual_call_info.accessed_storage_keys,
        HashSet::from([get_storage_var_address("number_map", &[felt!(1_u8)])])
    );

    // Test raw storage read and write.
    let key_int = 1234_u16;
    let key = felt!(key_int);
    let value = felt!(18_u8);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        ..trivial_external_entry_point_new(test_contract)
    };
    let actual_call_info = entry_point_call.execute_directly(&mut state).unwrap();
    assert_eq!(actual_call_info.storage_read_values, vec![value]);
    assert_eq!(actual_call_info.accessed_storage_keys, HashSet::from([storage_key!(key_int)]));
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

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().resources.builtin_instance_counter
            [&BuiltinName::segment_arena],
        // Note: the number of segment_arena instances should not depend on the compiler or VM
        // version. Do not manually fix this then when upgrading them - it might be a bug.
        2
    );
}
