use std::collections::{HashMap, HashSet};

use cairo_vm::vm::runners::builtin_runner::RANGE_CHECK_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use num_traits::Pow;
use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::core::{
    calculate_contract_address, ChainId, ClassHash, ContractAddress, Nonce, PatriciaKey,
};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, Fee, TransactionHash, TransactionVersion,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key};
use starknet_types_core::felt::Felt;
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::execution::call_info::{CallExecution, CallInfo, Retdata};
use crate::execution::common_hints::ExecutionMode;
use crate::execution::entry_point::{CallEntryPoint, CallType};
use crate::execution::errors::{EntryPointExecutionError, VirtualMachineExecutionError};
use crate::state::state_api::StateReader;
use crate::test_utils::cached_state::{
    deprecated_create_deploy_test_state, deprecated_create_test_state,
};
use crate::test_utils::{
    trivial_external_entry_point, CHAIN_ID_NAME, CURRENT_BLOCK_NUMBER, CURRENT_BLOCK_TIMESTAMP,
    TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS, TEST_EMPTY_CONTRACT_CLASS_HASH, TEST_SEQUENCER_ADDRESS,
};
use crate::transaction::constants::QUERY_VERSION_BASE_BIT;
use crate::transaction::objects::{
    AccountTransactionContext, CommonAccountFields, DeprecatedAccountTransactionContext,
};
use crate::{check_entry_point_execution_error_for_custom_hint, retdata};

#[test]
fn test_storage_read_write() {
    let mut state = deprecated_create_test_state();
    let key = Felt::from(1234_u16);
    let value = Felt::from(18_u8);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        ..trivial_external_entry_point()
    };
    let storage_address = entry_point_call.storage_address;
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![value])
    );
    // Verify that the state has changed.
    let value_from_state =
        state.get_storage_at(storage_address, StorageKey::try_from(key).unwrap()).unwrap();
    assert_eq!(value_from_state, value);
}

#[test]
fn test_library_call() {
    let mut state = deprecated_create_test_state();
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let calldata = calldata![
        Felt::from(TEST_CLASS_HASH),  // Class hash.
        inner_entry_point_selector.0, // Function selector.
        Felt::TWO,                    // Calldata length.
        Felt::from(1234_u16),         // Calldata: address.
        Felt::from(91_u16)            // Calldata: value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_library_call"),
        calldata,
        class_hash: Some(class_hash!(TEST_CLASS_HASH)),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![Felt::from(91_u16)])
    );
}

#[test]
fn test_nested_library_call() {
    let mut state = deprecated_create_test_state();
    let (key, value) = (255_u64, 44_u64);
    let outer_entry_point_selector = selector_from_name("test_library_call");
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let main_entry_point_calldata = calldata![
        Felt::from(TEST_CLASS_HASH),  // Class hash.
        outer_entry_point_selector.0, // Library call function selector.
        inner_entry_point_selector.0, // Storage function selector.
        Felt::TWO,                    // Calldata length.
        Felt::from(key),              // Calldata: address.
        Felt::from(value)             // Calldata: value.
    ];

    // Create expected call info tree.
    let main_entry_point = CallEntryPoint {
        entry_point_selector: selector_from_name("test_nested_library_call"),
        calldata: main_entry_point_calldata,
        class_hash: Some(class_hash!(TEST_CLASS_HASH)),
        ..trivial_external_entry_point()
    };
    let nested_storage_entry_point = CallEntryPoint {
        entry_point_selector: inner_entry_point_selector,
        calldata: calldata![Felt::from(key + 1), Felt::from(value + 1)],
        class_hash: Some(class_hash!(TEST_CLASS_HASH)),
        code_address: None,
        call_type: CallType::Delegate,
        ..trivial_external_entry_point()
    };
    let library_entry_point = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata: calldata![
            Felt::from(TEST_CLASS_HASH),  // Class hash.
            inner_entry_point_selector.0, // Storage function selector.
            Felt::TWO,                    // Calldata length.
            Felt::from(key + 1),          // Calldata: address.
            Felt::from(value + 1)         // Calldata: value.
        ],
        class_hash: Some(class_hash!(TEST_CLASS_HASH)),
        code_address: None,
        call_type: CallType::Delegate,
        ..trivial_external_entry_point()
    };
    let storage_entry_point = CallEntryPoint {
        calldata: calldata![Felt::from(key), Felt::from(value)],
        ..nested_storage_entry_point
    };
    let storage_entry_point_vm_resources =
        VmExecutionResources { n_steps: 42, ..Default::default() };
    let nested_storage_call_info = CallInfo {
        call: nested_storage_entry_point,
        execution: CallExecution::from_retdata(retdata![Felt::from(value + 1)]),
        vm_resources: storage_entry_point_vm_resources.clone(),
        storage_read_values: vec![Felt::ZERO, Felt::from(value + 1)],
        accessed_storage_keys: HashSet::from([StorageKey(patricia_key!(key + 1))]),
        ..Default::default()
    };
    let mut library_call_vm_resources = VmExecutionResources {
        n_steps: 39,
        builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 1)]),
        ..Default::default()
    };
    library_call_vm_resources += &storage_entry_point_vm_resources;
    let library_call_info = CallInfo {
        call: library_entry_point,
        execution: CallExecution::from_retdata(retdata![Felt::from(value + 1)]),
        vm_resources: library_call_vm_resources.clone(),
        inner_calls: vec![nested_storage_call_info],
        ..Default::default()
    };
    let storage_call_info = CallInfo {
        call: storage_entry_point,
        execution: CallExecution::from_retdata(retdata![Felt::from(value)]),
        vm_resources: storage_entry_point_vm_resources.clone(),
        storage_read_values: vec![Felt::ZERO, Felt::from(value)],
        accessed_storage_keys: HashSet::from([StorageKey(patricia_key!(key))]),
        ..Default::default()
    };

    // Nested library call cost: library_call(inner) + library_call(library_call(inner)).
    let mut main_call_vm_resources = VmExecutionResources { n_steps: 45, ..Default::default() };
    main_call_vm_resources += &(&library_call_vm_resources * 2);
    let expected_call_info = CallInfo {
        call: main_entry_point.clone(),
        execution: CallExecution::from_retdata(retdata![Felt::ZERO]),
        vm_resources: main_call_vm_resources,
        inner_calls: vec![library_call_info, storage_call_info],
        ..Default::default()
    };

    assert_eq!(main_entry_point.execute_directly(&mut state).unwrap(), expected_call_info);
}

#[test]
fn test_call_contract() {
    let mut state = deprecated_create_test_state();
    let outer_entry_point_selector = selector_from_name("test_call_contract");
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let (key, value) = (Felt::from(405_u16), Felt::from(48_u8));
    let inner_calldata = calldata![key, value];
    let calldata = calldata![
        Felt::from(TEST_CONTRACT_ADDRESS), // Contract address.
        inner_entry_point_selector.0,      // Function selector.
        Felt::TWO,                         // Calldata length.
        key,                               // Calldata: address.
        value                              // Calldata: value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata: calldata.clone(),
        ..trivial_external_entry_point()
    };
    let call_info = entry_point_call.execute_directly(&mut state).unwrap();

    let expected_execution = CallExecution { retdata: retdata![value], ..Default::default() };
    let expected_inner_call_info = CallInfo {
        call: CallEntryPoint {
            class_hash: Some(class_hash!(TEST_CLASS_HASH)),
            code_address: Some(contract_address!(TEST_CONTRACT_ADDRESS)),
            entry_point_selector: inner_entry_point_selector,
            calldata: inner_calldata,
            storage_address: contract_address!(TEST_CONTRACT_ADDRESS),
            caller_address: contract_address!(TEST_CONTRACT_ADDRESS),
            ..trivial_external_entry_point()
        },
        execution: expected_execution.clone(),
        vm_resources: VmExecutionResources { n_steps: 42, ..Default::default() },
        storage_read_values: vec![Felt::ZERO, value],
        accessed_storage_keys: HashSet::from([StorageKey(patricia_key!(key))]),
        ..Default::default()
    };
    let expected_call_info = CallInfo {
        inner_calls: vec![expected_inner_call_info],
        call: CallEntryPoint {
            class_hash: Some(class_hash!(TEST_CLASS_HASH)),
            code_address: Some(contract_address!(TEST_CONTRACT_ADDRESS)),
            entry_point_selector: outer_entry_point_selector,
            calldata,
            storage_address: contract_address!(TEST_CONTRACT_ADDRESS),
            ..trivial_external_entry_point()
        },
        execution: expected_execution,
        vm_resources: VmExecutionResources {
            n_steps: 81,
            builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 1)]),
            ..Default::default()
        },
        ..Default::default()
    };

    assert_eq!(expected_call_info, call_info);
}

#[test]
fn test_replace_class() {
    // Negative flow.
    let mut state = deprecated_create_deploy_test_state();
    // Replace with undeclared class hash.
    let calldata = calldata![Felt::from(1234_u16)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point()
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert!(error.contains("is not declared"));

    // Positive flow.
    let contract_address = contract_address!(TEST_CONTRACT_ADDRESS);
    let old_class_hash = class_hash!(TEST_CLASS_HASH);
    let new_class_hash = class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH);
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), old_class_hash);
    let entry_point_call = CallEntryPoint {
        calldata: calldata![new_class_hash.0],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point()
    };
    entry_point_call.execute_directly(&mut state).unwrap();
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), new_class_hash);
}

#[test_case(
    class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
    calldata![
    Felt::from(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
    ContractAddressSalt::default().0, // Contract_address_salt.
    Felt::ZERO, // Calldata length.
    Felt::ZERO // deploy_from_zero.
    ],
    calldata![],
    None ;
    "No constructor: Positive flow")]
#[test_case(
    class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
    calldata![
        Felt::from(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        Felt::TWO, // Calldata length.
        Felt::TWO, // Calldata: address.
        Felt::ONE, // Calldata: value.
        Felt::ZERO // deploy_from_zero.
    ],
    calldata![
        Felt::TWO, // Calldata: address.
        Felt::ONE // Calldata: value.
    ],
    Some(
    "Invalid input: constructor_calldata; Cannot pass calldata to a contract with no constructor.");
    "No constructor: Negative flow: nonempty calldata")]
#[test_case(
    class_hash!(TEST_CLASS_HASH),
    calldata![
        Felt::from(TEST_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        Felt::TWO, // Calldata length.
        Felt::ONE, // Calldata: address.
        Felt::ONE, // Calldata: value.
        Felt::ZERO // deploy_from_zero.
    ],
    calldata![
        Felt::ONE, // Calldata: address.
        Felt::ONE // Calldata: value.
    ],
    None;
    "With constructor: Positive flow")]
#[test_case(
    class_hash!(TEST_CLASS_HASH),
    calldata![
        Felt::from(TEST_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        Felt::TWO, // Calldata length.
        Felt::THREE, // Calldata: address.
        Felt::THREE, // Calldata: value.
        Felt::ZERO // deploy_from_zero.
    ],
    calldata![
        Felt::THREE, // Calldata: address.
        Felt::THREE // Calldata: value.
    ],
    Some("is unavailable for deployment.");
    "With constructor: Negative flow: deploy to the same address")]
#[test_case(
    class_hash!(TEST_CLASS_HASH),
    calldata![
        Felt::from(TEST_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        Felt::TWO, // Calldata length.
        Felt::ONE, // Calldata: address.
        Felt::ONE, // Calldata: value.
        Felt::TWO // deploy_from_zero.
    ],
    calldata![
        Felt::ONE, // Calldata: address.
        Felt::ONE // Calldata: value.
    ],
    Some(&format!(
        "Invalid syscall input: {:?}; {:}",
        Felt::TWO,
        "The deploy_from_zero field in the deploy system call must be 0 or 1.",
    ));
    "With constructor: Negative flow: illegal value for deploy_from_zero")]
fn test_deploy(
    class_hash: ClassHash,
    calldata: Calldata,
    constructor_calldata: Calldata,
    expected_error: Option<&str>,
) {
    let mut state = deprecated_create_deploy_test_state();
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_deploy"),
        calldata,
        ..trivial_external_entry_point()
    };

    if let Some(expected_error) = expected_error {
        let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
        assert!(error.contains(expected_error));
        return;
    }

    // No errors expected.
    let contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &constructor_calldata,
        contract_address!(TEST_CONTRACT_ADDRESS),
    )
    .unwrap();
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![contract_address.0.to_felt()])
    );
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), class_hash);
}

#[test_case(
    ExecutionMode::Execute, "block_number", calldata![Felt::from(CURRENT_BLOCK_NUMBER)];
    "Test the syscall get_block_number in execution mode Execute")]
#[test_case(
    ExecutionMode::Validate, "block_number", calldata![Felt::from(CURRENT_BLOCK_NUMBER)];
    "Test the syscall get_block_number in execution mode Validate")]
#[test_case(
    ExecutionMode::Execute, "block_timestamp", calldata![Felt::from(CURRENT_BLOCK_TIMESTAMP)];
    "Test the syscall get_block_timestamp in execution mode Execute")]
#[test_case(
    ExecutionMode::Validate, "block_timestamp", calldata![Felt::from(CURRENT_BLOCK_TIMESTAMP)];
    "Test the syscall get_block_timestamp in execution mode Validate")]
#[test_case(
    ExecutionMode::Execute, "sequencer_address", calldata![Felt::from(TEST_SEQUENCER_ADDRESS)];
    "Test the syscall get_sequencer_address in execution mode Execute")]
#[test_case(
    ExecutionMode::Validate, "sequencer_address", calldata![Felt::ZERO];
    "Test the syscall get_sequencer_address in execution mode Validate")]
fn test_block_info_syscalls(
    execution_mode: ExecutionMode,
    block_info_member_name: &str,
    calldata: Calldata,
) {
    let mut state = deprecated_create_test_state();
    let entry_point_selector = selector_from_name(&format!("test_get_{}", block_info_member_name));
    let entry_point_call =
        CallEntryPoint { entry_point_selector, calldata, ..trivial_external_entry_point() };

    if execution_mode == ExecutionMode::Validate && block_info_member_name == "sequencer_address" {
        let error = entry_point_call.execute_directly_in_validate_mode(&mut state).unwrap_err();
        check_entry_point_execution_error_for_custom_hint!(
            &error,
            &format!(
                "Unauthorized syscall get_{} in execution mode Validate.",
                block_info_member_name
            ),
        );
    } else {
        assert_eq!(
            entry_point_call.execute_directly(&mut state).unwrap().execution,
            CallExecution::from_retdata(retdata![])
        );
    }
}

#[rstest]
#[case(true)]
#[case(false)]
fn test_tx_info(#[case] only_query: bool) {
    let mut state = deprecated_create_deploy_test_state();
    let mut version = Felt::ONE;
    if only_query {
        let simulate_version_base = Pow::pow(Felt::TWO, QUERY_VERSION_BASE_BIT);
        version += simulate_version_base;
    }
    let tx_hash = TransactionHash(Felt::from(1991_u16));
    let max_fee = Fee(0);
    let nonce = Nonce(Felt::from(3_u16));
    let sender_address = ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS));
    let expected_tx_info = calldata![
        version,                                                               /* Transaction
                                                                                * version. */
        sender_address.0.to_felt(), // Account address.
        Felt::from(max_fee.0),      // Max fee.
        tx_hash.0,                  // Transaction hash.
        Felt::from_hex(&ChainId(CHAIN_ID_NAME.to_string()).as_hex()).unwrap(), // Chain ID.
        nonce.0                     // Nonce.
    ];
    let entry_point_selector = selector_from_name("test_get_tx_info");
    let entry_point_call = CallEntryPoint {
        entry_point_selector,
        calldata: expected_tx_info,
        ..trivial_external_entry_point()
    };
    let account_tx_context =
        AccountTransactionContext::Deprecated(DeprecatedAccountTransactionContext {
            common_fields: CommonAccountFields {
                transaction_hash: tx_hash,
                version: TransactionVersion::ONE,
                nonce,
                sender_address,
                only_query,
                ..Default::default()
            },
            max_fee,
        });
    let result = entry_point_call
        .execute_directly_given_account_context(&mut state, account_tx_context, true)
        .unwrap();

    assert!(!result.execution.failed)
}
