use std::collections::HashSet;

use cairo_vm::serde::deserialize_program::BuiltinName;
use num_bigint::BigInt;
use pretty_assertions::assert_eq;
use regex::Regex;
use rstest::rstest;
use starknet_api::core::{EntryPointSelector, PatriciaKey};
use starknet_api::deprecated_contract_class::{EntryPointOffset, EntryPointType};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{Calldata, TransactionVersion};
use starknet_api::{calldata, stark_felt};

use crate::abi::abi_utils::{get_storage_var_address, selector_from_name};
use crate::context::{BlockContext, ChainInfo};
use crate::execution::call_info::{CallExecution, CallInfo, Retdata};
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::CallEntryPoint;
use crate::state::cached_state::CachedState;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{
    create_calldata, trivial_external_entry_point_new, CairoVersion, NonceManager, BALANCE,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants::{
    EXECUTE_ENTRY_POINT_NAME, VALIDATE_DECLARE_ENTRY_POINT_NAME, VALIDATE_DEPLOY_ENTRY_POINT_NAME,
    VALIDATE_ENTRY_POINT_NAME,
};
use crate::transaction::test_utils::{
    block_context, create_account_tx_for_validate_test, run_invoke_tx, FaultyAccountTxCreatorArgs,
    INVALID,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transactions::ExecutableTransaction;
use crate::versioned_constants::VersionedConstants;
use crate::{invoke_tx_args, retdata, storage_key};

const INNER_CALL_CONTRACT_IN_CALL_CHAIN_OFFSET: usize = 117;

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

    for (i, call_info) in root.iter().enumerate() {
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
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("without_arg"),
        ..trivial_external_entry_point_new(test_contract)
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state, None).unwrap().execution,
        CallExecution::default()
    );
}

#[test]
fn test_entry_point_with_arg() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let calldata = calldata![stark_felt!(25_u8)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("with_arg"),
        ..trivial_external_entry_point_new(test_contract)
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state, None).unwrap().execution,
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
        entry_point_call.execute_directly(&mut state, None).unwrap().execution,
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
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let calldata = calldata![stark_felt!(47_u8), stark_felt!(31_u8)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("bitwise_and"),
        ..trivial_external_entry_point_new(test_contract)
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state, None).unwrap().execution,
        CallExecution::default()
    );
}

#[test]
fn test_entry_point_with_hint() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let calldata = calldata![stark_felt!(81_u8)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("sqrt"),
        ..trivial_external_entry_point_new(test_contract)
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state, None).unwrap().execution,
        CallExecution::default()
    );
}

#[test]
fn test_entry_point_with_return_value() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let calldata = calldata![stark_felt!(23_u8)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("return_result"),
        ..trivial_external_entry_point_new(test_contract)
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state, None).unwrap().execution,
        CallExecution::from_retdata(retdata![stark_felt!(23_u8)])
    );
}

#[test]
fn test_entry_point_not_found_in_contract() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let entry_point_selector = EntryPointSelector(stark_felt!(2_u8));
    let entry_point_call =
        CallEntryPoint { entry_point_selector, ..trivial_external_entry_point_new(test_contract) };
    let error = entry_point_call.execute_directly(&mut state, None).unwrap_err();
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
        entry_point_call.execute_directly(&mut state, None).unwrap().execution,
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
    let error = match entry_point_call.execute_directly(state, None) {
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
#[test]
fn test_storage_related_members() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);

    // Test storage variable.
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_storage_var"),
        ..trivial_external_entry_point_new(test_contract)
    };
    let actual_call_info = entry_point_call.execute_directly(&mut state, None).unwrap();
    assert_eq!(actual_call_info.storage_read_values, vec![stark_felt!(39_u8)]);
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
        ..trivial_external_entry_point_new(test_contract)
    };
    let actual_call_info = entry_point_call.execute_directly(&mut state, None).unwrap();
    assert_eq!(actual_call_info.storage_read_values, vec![value]);
    assert_eq!(actual_call_info.accessed_storage_keys, HashSet::from([storage_key!(key)]));
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
            .execute_directly(&mut state, None)
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
        ContractClass::V1(class) => {
            class
                .entry_points_by_type
                .get(&EntryPointType::External)
                .unwrap()
                .iter()
                .find(|ep| ep.selector == entry_point_selector)
                .unwrap()
                .offset
        }
        ContractClass::V1Sierra(_) => {
            panic!("Expected V0 or V1, found V1Sierra in entry point tests")
        }
    }
}

#[rstest]
fn test_stack_trace(
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let chain_info = ChainInfo::create_for_testing();
    let account = FeatureContract::AccountWithoutValidations(cairo_version);
    let test_contract = FeatureContract::TestContract(cairo_version);
    let mut state = test_state(&chain_info, BALANCE, &[(account, 1), (test_contract, 2)]);
    let account_address = account.get_instance_address(0);
    let test_contract_address = test_contract.get_instance_address(0);
    let test_contract_address_2 = test_contract.get_instance_address(1);
    let account_address_felt = *account_address.0.key();
    let test_contract_address_felt = *test_contract_address.0.key();
    let test_contract_address_2_felt = *test_contract_address_2.0.key();
    let test_contract_hash = test_contract.get_class_hash().0;
    let account_contract_hash = account.get_class_hash().0;

    // Nest calls: __execute__ -> test_call_contract -> assert_0_is_1.
    let call_contract_function_name = "test_call_contract";
    let inner_entry_point_selector_felt = selector_from_name("fail").0;
    let calldata = create_calldata(
        test_contract_address, // contract_address
        call_contract_function_name,
        &[
            test_contract_address_2_felt,    // Contract address.
            inner_entry_point_selector_felt, // Function selector.
            stark_felt!(0_u8),               // Innermost calldata length.
        ],
    );

    let tx_execution_error = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            sender_address: account_address,
            calldata,
            version: TransactionVersion::ZERO,
        },
    )
    .unwrap_err();

    // Fetch PC locations from the compiled contract to compute the expected PC locations in the
    // traceback. Computation is not robust, but as long as the cairo function itself is not edited,
    // this computation should be stable.
    let account_contract_class = account.get_class();
    let account_entry_point_offset = get_entry_point_offset(
        &account_contract_class,
        selector_from_name(EXECUTE_ENTRY_POINT_NAME),
    );
    let execute_selector_felt = selector_from_name(EXECUTE_ENTRY_POINT_NAME).0;
    let contract_class = test_contract.get_class();
    let external_entry_point_selector_felt = selector_from_name(call_contract_function_name).0;
    let entry_point_offset =
        get_entry_point_offset(&contract_class, selector_from_name(call_contract_function_name));
    // Relative offsets of the test_call_contract entry point and the inner call.
    let call_location = entry_point_offset.0 + 14;
    let entry_point_location = entry_point_offset.0 - 3;
    // Relative offsets of the account contract.
    let account_call_location = account_entry_point_offset.0 + 18;
    let account_entry_point_location = account_entry_point_offset.0 - 8;

    let expected_trace_cairo0 = format!(
        "Transaction execution has failed:
0: Error in the called contract (contract address: {account_address_felt}, class hash: \
         {account_contract_hash}, selector: {execute_selector_felt}):
Error at pc=0:7:
Cairo traceback (most recent call last):
Unknown location (pc=0:{account_call_location})
Unknown location (pc=0:{account_entry_point_location})

1: Error in the called contract (contract address: {test_contract_address_felt}, class hash: \
         {test_contract_hash}, selector: {external_entry_point_selector_felt}):
Error at pc=0:37:
Cairo traceback (most recent call last):
Unknown location (pc=0:{call_location})
Unknown location (pc=0:{entry_point_location})

2: Error in the called contract (contract address: {test_contract_address_2_felt}, class hash: \
         {test_contract_hash}, selector: {inner_entry_point_selector_felt}):
Error at pc=0:1184:
Cairo traceback (most recent call last):
Unknown location (pc=0:1188)

An ASSERT_EQ instruction failed: 1 != 0.
"
    );

    let expected_trace_cairo1 = format!(
        "Transaction execution has failed:
0: Error in the called contract (contract address: {account_address_felt}, class hash: \
         {account_contract_hash}, selector: {execute_selector_felt}):
Error at pc=0:767:
1: Error in the called contract (contract address: {test_contract_address_felt}, class hash: \
         {test_contract_hash}, selector: {external_entry_point_selector_felt}):
Error at pc=0:612:
2: Error in the called contract (contract address: {test_contract_address_2_felt}, class hash: \
         {test_contract_hash}, selector: {inner_entry_point_selector_felt}):
Execution failed. Failure reason: 0x6661696c ('fail').
"
    );

    let expected_trace = match cairo_version {
        CairoVersion::Cairo0 => expected_trace_cairo0,
        CairoVersion::Cairo1 => expected_trace_cairo1,
    };

    assert_eq!(tx_execution_error.to_string(), expected_trace);
}

#[rstest]
#[case(CairoVersion::Cairo0, "invoke_call_chain", "Couldn't compute operand op0. Unknown value for memory cell 1:37", (1081_u16, 1127_u16))]
#[case(CairoVersion::Cairo0, "fail", "An ASSERT_EQ instruction failed: 1 != 0.", (1184_u16, 1135_u16))]
#[case(CairoVersion::Cairo1, "invoke_call_chain", "0x4469766973696f6e2062792030 ('Division by 0')", (0_u16, 0_u16))]
#[case(CairoVersion::Cairo1, "fail", "0x6661696c ('fail')", (0_u16, 0_u16))]
fn test_trace_callchain_ends_with_regular_call(
    block_context: BlockContext,
    #[case] cairo_version: CairoVersion,
    #[case] last_func_name: &str,
    #[case] expected_error: &str,
    #[case] expected_pc_locations: (u16, u16),
) {
    let chain_info = ChainInfo::create_for_testing();
    let account_contract = FeatureContract::AccountWithoutValidations(cairo_version);
    let test_contract = FeatureContract::TestContract(cairo_version);
    let mut state = test_state(&chain_info, BALANCE, &[(account_contract, 1), (test_contract, 1)]);

    let account_address = account_contract.get_instance_address(0);
    let test_contract_address = test_contract.get_instance_address(0);
    let account_address_felt = *account_address.0.key();
    let contract_address_felt = *test_contract_address.0.key();
    let test_contract_hash = test_contract.get_class_hash().0;
    let account_contract_hash = account_contract.get_class_hash().0;

    // invoke_call_chain -> call_contract_syscall invoke_call_chain -> regular call to final func.
    let invoke_call_chain_selector = selector_from_name("invoke_call_chain");
    let invoke_call_chain_selector_felt = invoke_call_chain_selector.0;

    let calldata = create_calldata(
        test_contract_address, // contract_address
        "invoke_call_chain",
        &[
            stark_felt!(7_u8),                    // Calldata length
            contract_address_felt,                // Contract address.
            invoke_call_chain_selector_felt,      // Function selector.
            stark_felt!(0_u8),                    // Call type: call_contract_syscall.
            stark_felt!(3_u8),                    // Calldata length
            contract_address_felt,                // Contract address.
            selector_from_name(last_func_name).0, // Function selector.
            stark_felt!(2_u8),                    // Call type: regular call.
        ],
    );

    let tx_execution_error = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            sender_address: account_address,
            calldata,
            version: TransactionVersion::ZERO,
        },
    )
    .unwrap_err();

    let account_entry_point_offset = get_entry_point_offset(
        &account_contract.get_class(),
        selector_from_name(EXECUTE_ENTRY_POINT_NAME),
    );
    let entry_point_offset =
        get_entry_point_offset(&test_contract.get_class(), invoke_call_chain_selector);
    let execute_selector_felt = selector_from_name(EXECUTE_ENTRY_POINT_NAME).0;

    let expected_trace = match cairo_version {
        CairoVersion::Cairo0 => {
            let call_location = entry_point_offset.0 + 12;
            let entry_point_location = entry_point_offset.0 - 61;
            // Relative offsets of the account contract.
            let account_call_location = account_entry_point_offset.0 + 18;
            let account_entry_point_location = account_entry_point_offset.0 - 8;
            // Final invocation locations.
            let (expected_pc0, expected_pc1) = expected_pc_locations;
            format!(
                "Transaction execution has failed:
0: Error in the called contract (contract address: {account_address_felt}, class hash: \
                 {account_contract_hash}, selector: {execute_selector_felt}):
Error at pc=0:7:
Cairo traceback (most recent call last):
Unknown location (pc=0:{account_call_location})
Unknown location (pc=0:{account_entry_point_location})

1: Error in the called contract (contract address: {contract_address_felt}, class hash: \
                 {test_contract_hash}, selector: {invoke_call_chain_selector_felt}):
Error at pc=0:37:
Cairo traceback (most recent call last):
Unknown location (pc=0:{call_location})
Unknown location (pc=0:{entry_point_location})

2: Error in the called contract (contract address: {contract_address_felt}, class hash: \
                 {test_contract_hash}, selector: {invoke_call_chain_selector_felt}):
Error at pc=0:{expected_pc0}:
Cairo traceback (most recent call last):
Unknown location (pc=0:{call_location})
Unknown location (pc=0:{expected_pc1})

{expected_error}
"
            )
        }
        CairoVersion::Cairo1 => {
            let pc_location = entry_point_offset.0 + INNER_CALL_CONTRACT_IN_CALL_CHAIN_OFFSET;
            format!(
                "Transaction execution has failed:
0: Error in the called contract (contract address: {account_address_felt}, class hash: \
                 {account_contract_hash}, selector: {execute_selector_felt}):
Error at pc=0:767:
1: Error in the called contract (contract address: {contract_address_felt}, class hash: \
                 {test_contract_hash}, selector: {invoke_call_chain_selector_felt}):
Error at pc=0:9228:
Cairo traceback (most recent call last):
Unknown location (pc=0:{pc_location})

2: Error in the called contract (contract address: {contract_address_felt}, class hash: \
                 {test_contract_hash}, selector: {invoke_call_chain_selector_felt}):
Execution failed. Failure reason: {expected_error}.
"
            )
        }
    };

    assert_eq!(tx_execution_error.to_string(), expected_trace);
}

#[rstest]
#[case(CairoVersion::Cairo0, "invoke_call_chain", "Couldn't compute operand op0. Unknown value for memory cell 1:23", 1_u8, 0_u8, (37_u16, 1093_u16, 1081_u16, 1166_u16))]
#[case(CairoVersion::Cairo0, "invoke_call_chain", "Couldn't compute operand op0. Unknown value for memory cell 1:23", 1_u8, 1_u8, (49_u16, 1111_u16, 1081_u16, 1166_u16))]
#[case(CairoVersion::Cairo0, "fail", "An ASSERT_EQ instruction failed: 1 != 0.", 0_u8, 0_u8, (37_u16, 1093_u16, 1184_u16, 1188_u16))]
#[case(CairoVersion::Cairo0, "fail", "An ASSERT_EQ instruction failed: 1 != 0.", 0_u8, 1_u8, (49_u16, 1111_u16, 1184_u16, 1188_u16))]
#[case(CairoVersion::Cairo1, "invoke_call_chain", "0x4469766973696f6e2062792030 ('Division by 0')", 1_u8, 0_u8, (9228_u16, 9228_u16, 0_u16, 0_u16))]
#[case(CairoVersion::Cairo1, "invoke_call_chain", "0x4469766973696f6e2062792030 ('Division by 0')", 1_u8, 1_u8, (9228_u16, 9297_u16, 0_u16, 0_u16))]
#[case(CairoVersion::Cairo1, "fail", "0x6661696c ('fail')", 0_u8, 0_u8, (9228_u16, 9228_u16, 0_u16, 0_u16))]
#[case(CairoVersion::Cairo1, "fail", "0x6661696c ('fail')", 0_u8, 1_u8, (9228_u16, 9297_u16, 0_u16, 0_u16))]
fn test_trace_call_chain_with_syscalls(
    block_context: BlockContext,
    #[case] cairo_version: CairoVersion,
    #[case] last_func_name: &str,
    #[case] expected_error: &str,
    #[case] calldata_extra_length: u8,
    #[case] call_type: u8,
    #[case] expected_pcs: (u16, u16, u16, u16),
) {
    let chain_info = ChainInfo::create_for_testing();
    let account_contract = FeatureContract::AccountWithoutValidations(cairo_version);
    let test_contract = FeatureContract::TestContract(cairo_version);
    let mut state = test_state(&chain_info, BALANCE, &[(account_contract, 1), (test_contract, 1)]);

    let account_address = account_contract.get_instance_address(0);
    let test_contract_address = test_contract.get_instance_address(0);

    let test_contract_hash = test_contract.get_class_hash().0;
    let account_contract_hash = account_contract.get_class_hash().0;
    let account_address_felt = *account_address.0.key();
    let address_felt = *test_contract_address.0.key();
    let contract_id = if call_type == 0 { address_felt } else { test_contract_hash };

    // invoke_call_chain -> call_contract_syscall invoke_call_chain -> call_contract_syscall /
    // library_call_syscall to final func.
    let invoke_call_chain_selector = selector_from_name("invoke_call_chain");
    let invoke_call_chain_selector_felt = invoke_call_chain_selector.0;
    let last_func_selector_felt = selector_from_name(last_func_name).0;

    let mut raw_calldata = vec![
        stark_felt!(7_u8 + calldata_extra_length), // Calldata length
        address_felt,                              // Contract address.
        invoke_call_chain_selector_felt,           // Function selector.
        stark_felt!(0_u8),                         // Call type: call_contract_syscall.
        stark_felt!(3_u8 + calldata_extra_length), // Calldata length
        contract_id,                               // Contract address / class hash.
        last_func_selector_felt,                   // Function selector.
        stark_felt!(call_type),                    // Syscall type: library_call or call_contract.
    ];

    // Need to send an empty array for the last call in `invoke_call_chain` variant.
    if last_func_name == "invoke_call_chain" {
        raw_calldata.push(stark_felt!(0_u8));
    }

    let calldata = create_calldata(
        test_contract_address, // contract_address
        "invoke_call_chain",
        &raw_calldata,
    );

    let tx_execution_error = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            sender_address: account_address,
            calldata,
            version: TransactionVersion::ZERO,
        },
    )
    .unwrap_err();

    let account_entry_point_offset = get_entry_point_offset(
        &account_contract.get_class(),
        selector_from_name(EXECUTE_ENTRY_POINT_NAME),
    );
    let entry_point_offset =
        get_entry_point_offset(&test_contract.get_class(), invoke_call_chain_selector);
    let execute_selector_felt = selector_from_name(EXECUTE_ENTRY_POINT_NAME).0;

    let last_call_preamble = if call_type == 0 {
        format!(
            "Error in the called contract (contract address: {address_felt}, class hash: \
             {test_contract_hash}, selector: {last_func_selector_felt})"
        )
    } else {
        format!(
            "Error in a library call (contract address: {address_felt}, class hash: \
             {test_contract_hash}, selector: {last_func_selector_felt})"
        )
    };

    let expected_trace = match cairo_version {
        CairoVersion::Cairo0 => {
            let call_location = entry_point_offset.0 + 12;
            let entry_point_location = entry_point_offset.0 - 61;
            // Relative offsets of the account contract.
            let account_call_location = account_entry_point_offset.0 + 18;
            let account_entry_point_location = account_entry_point_offset.0 - 8;
            let (expected_pc0, expected_pc1, expected_pc2, expected_pc3) = expected_pcs;
            format!(
                "Transaction execution has failed:
0: Error in the called contract (contract address: {account_address_felt}, class hash: \
                 {account_contract_hash}, selector: {execute_selector_felt}):
Error at pc=0:7:
Cairo traceback (most recent call last):
Unknown location (pc=0:{account_call_location})
Unknown location (pc=0:{account_entry_point_location})

1: Error in the called contract (contract address: {address_felt}, class hash: \
                 {test_contract_hash}, selector: {invoke_call_chain_selector_felt}):
Error at pc=0:37:
Cairo traceback (most recent call last):
Unknown location (pc=0:{call_location})
Unknown location (pc=0:{entry_point_location})

2: Error in the called contract (contract address: {address_felt}, class hash: \
                 {test_contract_hash}, selector: {invoke_call_chain_selector_felt}):
Error at pc=0:{expected_pc0}:
Cairo traceback (most recent call last):
Unknown location (pc=0:{call_location})
Unknown location (pc=0:{expected_pc1})

3: {last_call_preamble}:
Error at pc=0:{expected_pc2}:
Cairo traceback (most recent call last):
Unknown location (pc=0:{expected_pc3})

{expected_error}
"
            )
        }
        CairoVersion::Cairo1 => {
            let pc_location = entry_point_offset.0 + INNER_CALL_CONTRACT_IN_CALL_CHAIN_OFFSET;
            let (expected_pc0, expected_pc1, _, _) = expected_pcs;
            format!(
                "Transaction execution has failed:
0: Error in the called contract (contract address: {account_address_felt}, class hash: \
                 {account_contract_hash}, selector: {execute_selector_felt}):
Error at pc=0:767:
1: Error in the called contract (contract address: {address_felt}, class hash: \
                 {test_contract_hash}, selector: {invoke_call_chain_selector_felt}):
Error at pc=0:{expected_pc0}:
Cairo traceback (most recent call last):
Unknown location (pc=0:{pc_location})

2: Error in the called contract (contract address: {address_felt}, class hash: \
                 {test_contract_hash}, selector: {invoke_call_chain_selector_felt}):
Error at pc=0:{expected_pc1}:
Cairo traceback (most recent call last):
Unknown location (pc=0:{pc_location})

3: {last_call_preamble}:
Execution failed. Failure reason: {expected_error}.
"
            )
        }
    };

    assert_eq!(tx_execution_error.to_string(), expected_trace);
}

// TODO(Arni, 1/5/2024): Cover version 0 declare transaction.
// TODO(Arni, 1/5/2024): Consider version 0 invoke.
#[rstest]
#[case::validate_version_1(
    TransactionType::InvokeFunction,
    VALIDATE_ENTRY_POINT_NAME,
    TransactionVersion::ONE
)]
#[case::validate_version_3(
    TransactionType::InvokeFunction,
    VALIDATE_ENTRY_POINT_NAME,
    TransactionVersion::THREE
)]
#[case::validate_declare_version_1(
    TransactionType::Declare,
    VALIDATE_DECLARE_ENTRY_POINT_NAME,
    TransactionVersion::ONE
)]
#[case::validate_declare_version_2(
    TransactionType::Declare,
    VALIDATE_DECLARE_ENTRY_POINT_NAME,
    TransactionVersion::TWO
)]
#[case::validate_declare_version_3(
    TransactionType::Declare,
    VALIDATE_DECLARE_ENTRY_POINT_NAME,
    TransactionVersion::THREE
)]
#[case::validate_deploy_version_1(
    TransactionType::DeployAccount,
    VALIDATE_DEPLOY_ENTRY_POINT_NAME,
    TransactionVersion::ONE
)]
#[case::validate_deploy_version_3(
    TransactionType::DeployAccount,
    VALIDATE_DEPLOY_ENTRY_POINT_NAME,
    TransactionVersion::THREE
)]
fn test_validate_trace(
    #[case] tx_type: TransactionType,
    #[case] entry_point_name: &str,
    #[case] tx_version: TransactionVersion,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let create_for_account_testing = &BlockContext::create_for_account_testing();
    let block_context = create_for_account_testing;
    let faulty_account = FeatureContract::FaultyAccount(cairo_version);
    let mut sender_address = faulty_account.get_instance_address(0);
    let class_hash = faulty_account.get_class_hash();
    let state = &mut test_state(&block_context.chain_info, 0, &[(faulty_account, 1)]);
    let selector = selector_from_name(entry_point_name).0;

    // Logic failure.
    let account_tx = create_account_tx_for_validate_test(
        &mut NonceManager::default(),
        FaultyAccountTxCreatorArgs {
            scenario: INVALID,
            tx_type,
            tx_version,
            sender_address,
            class_hash,
            ..Default::default()
        },
    );

    if let TransactionType::DeployAccount = tx_type {
        // Deploy account uses the actual address as the sender address.
        match &account_tx {
            AccountTransaction::DeployAccount(tx) => {
                sender_address = tx.contract_address;
            }
            _ => panic!("Expected DeployAccountTransaction type"),
        }
    }

    let contract_address = *sender_address.0.key();

    let expected_error = match cairo_version {
        CairoVersion::Cairo0 => format!(
            "Transaction validation has failed:
0: Error in the called contract (contract address: {contract_address}, class hash: {class_hash}, \
             selector: {selector}):
Error at pc=0:0:
Cairo traceback (most recent call last):
Unknown location (pc=0:0)
Unknown location (pc=0:0)

An ASSERT_EQ instruction failed: 1 != 0.
"
        ),
        CairoVersion::Cairo1 => format!(
            "Transaction validation has failed:
0: Error in the called contract (contract address: {contract_address}, class hash: {class_hash}, \
             selector: {selector}):
Execution failed. Failure reason: 0x496e76616c6964207363656e6172696f ('Invalid scenario').
"
        ),
    };

    // Clean pc locations from the trace.
    let re = Regex::new(r"pc=0:[0-9]+").unwrap();
    let cleaned_expected_error = &re.replace_all(&expected_error, "pc=0:*");
    let actual_error = account_tx.execute(state, block_context, true, true, None).unwrap_err();
    let actual_error_str = actual_error.to_string();
    let cleaned_actual_error = &re.replace_all(&actual_error_str, "pc=0:*");
    // Compare actual trace to the expected trace (sans pc locations).
    assert_eq!(cleaned_actual_error.to_string(), cleaned_expected_error.to_string());
}
