use std::collections::{HashMap, HashSet};

use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use num_traits::Pow;
use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::core::{calculate_contract_address, ChainId, PatriciaKey};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, EventContent, EventData, EventKey, Fee, TransactionHash,
    TransactionVersion,
};
use starknet_api::{calldata, felt};
use starknet_types_core::felt::Felt;
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::context::ChainInfo;
use crate::execution::call_info::{CallExecution, CallInfo, OrderedEvent, Retdata};
use crate::execution::common_hints::ExecutionMode;
use crate::execution::deprecated_syscalls::DeprecatedSyscallSelector;
use crate::execution::entry_point::{CallEntryPoint, CallType};
use crate::execution::errors::EntryPointExecutionError;
use crate::execution::syscalls::hint_processor::EmitEventError;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{
    calldata_for_deploy_test, get_syscall_resources, trivial_external_entry_point_new,
    CairoVersion, CHAIN_ID_NAME, CURRENT_BLOCK_NUMBER, CURRENT_BLOCK_NUMBER_FOR_VALIDATE,
    CURRENT_BLOCK_TIMESTAMP, CURRENT_BLOCK_TIMESTAMP_FOR_VALIDATE, TEST_SEQUENCER_ADDRESS,
};
use crate::transaction::constants::QUERY_VERSION_BASE_BIT;
use crate::transaction::objects::{
    CommonAccountFields, DeprecatedTransactionInfo, TransactionInfo,
};
use crate::versioned_constants::VersionedConstants;
use crate::{check_entry_point_execution_error_for_custom_hint, nonce, retdata, storage_key};

#[test]
fn test_storage_read_write() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);

    let key = felt!(1234_u16);
    let value = felt!(18_u8);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        ..trivial_external_entry_point_new(test_contract)
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
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let calldata = calldata![
        test_contract.get_class_hash().0, // Class hash.
        inner_entry_point_selector.0,     // Function selector.
        felt!(2_u8),                      // Calldata length.
        felt!(1234_u16),                  // Calldata: address.
        felt!(91_u16)                     // Calldata: value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_library_call"),
        calldata,
        class_hash: Some(test_contract.get_class_hash()),
        ..trivial_external_entry_point_new(test_contract)
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![felt!(91_u16)])
    );
}

#[test]
fn test_nested_library_call() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let (key, value) = (255_u64, 44_u64);
    let outer_entry_point_selector = selector_from_name("test_library_call");
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let main_entry_point_calldata = calldata![
        test_contract.get_class_hash().0, // Class hash.
        outer_entry_point_selector.0,     // Library call function selector.
        inner_entry_point_selector.0,     // Storage function selector.
        felt!(2_u8),                      // Calldata length.
        felt!(key),                       // Calldata: address.
        felt!(value)                      // Calldata: value.
    ];

    // Create expected call info tree.
    let main_entry_point = CallEntryPoint {
        entry_point_selector: selector_from_name("test_nested_library_call"),
        calldata: main_entry_point_calldata,
        class_hash: Some(test_contract.get_class_hash()),
        ..trivial_external_entry_point_new(test_contract)
    };
    let nested_storage_entry_point = CallEntryPoint {
        entry_point_selector: inner_entry_point_selector,
        calldata: calldata![felt!(key + 1), felt!(value + 1)],
        class_hash: Some(test_contract.get_class_hash()),
        code_address: None,
        call_type: CallType::Delegate,
        ..trivial_external_entry_point_new(test_contract)
    };
    let library_entry_point = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata: calldata![
            test_contract.get_class_hash().0, // Class hash.
            inner_entry_point_selector.0,     // Storage function selector.
            felt!(2_u8),                      // Calldata length.
            felt!(key + 1),                   // Calldata: address.
            felt!(value + 1)                  // Calldata: value.
        ],
        class_hash: Some(test_contract.get_class_hash()),
        code_address: None,
        call_type: CallType::Delegate,
        ..trivial_external_entry_point_new(test_contract)
    };
    let storage_entry_point = CallEntryPoint {
        calldata: calldata![felt!(key), felt!(value)],
        ..nested_storage_entry_point
    };
    let storage_entry_point_resources = ExecutionResources {
        n_steps: 218,
        n_memory_holes: 0,
        builtin_instance_counter: HashMap::from([(BuiltinName::range_check, 2)]),
    };
    let nested_storage_call_info = CallInfo {
        call: nested_storage_entry_point,
        execution: CallExecution::from_retdata(retdata![felt!(value + 1)]),
        resources: storage_entry_point_resources.clone(),
        storage_read_values: vec![felt!(value + 1)],
        accessed_storage_keys: HashSet::from([storage_key!(key + 1)]),
        ..Default::default()
    };
    let mut library_call_resources = &get_syscall_resources(DeprecatedSyscallSelector::LibraryCall)
        + &ExecutionResources {
            n_steps: 39,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::from([(BuiltinName::range_check, 1)]),
        };
    library_call_resources += &storage_entry_point_resources;
    let library_call_info = CallInfo {
        call: library_entry_point,
        execution: CallExecution::from_retdata(retdata![felt!(value + 1)]),
        resources: library_call_resources.clone(),
        inner_calls: vec![nested_storage_call_info],
        ..Default::default()
    };
    let storage_call_info = CallInfo {
        call: storage_entry_point,
        execution: CallExecution::from_retdata(retdata![felt!(value)]),
        resources: storage_entry_point_resources.clone(),
        storage_read_values: vec![felt!(value)],
        accessed_storage_keys: HashSet::from([storage_key!(key)]),
        ..Default::default()
    };

    // Nested library call cost: library_call(inner) + library_call(library_call(inner)).
    let mut main_call_resources = &get_syscall_resources(DeprecatedSyscallSelector::LibraryCall)
        + &ExecutionResources {
            n_steps: 45,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::new(),
        };
    main_call_resources += &(&library_call_resources * 2);
    let expected_call_info = CallInfo {
        call: main_entry_point.clone(),
        execution: CallExecution::from_retdata(retdata![felt!(0_u8)]),
        resources: main_call_resources,
        inner_calls: vec![library_call_info, storage_call_info],
        ..Default::default()
    };

    assert_eq!(main_entry_point.execute_directly(&mut state).unwrap(), expected_call_info);
}

#[test]
fn test_call_contract() {
    let chain_info = &ChainInfo::create_for_testing();
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(chain_info, 0, &[(test_contract, 1)]);
    let test_address = test_contract.get_instance_address(0);

    let trivial_external_entry_point = trivial_external_entry_point_new(test_contract);
    let outer_entry_point_selector = selector_from_name("test_call_contract");
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let (key_int, value_int) = (405_u16, 48_u8);
    let (key, value) = (felt!(key_int), felt!(value_int));
    let inner_calldata = calldata![key, value];
    let calldata = calldata![
        *test_address.0.key(),        // Contract address.
        inner_entry_point_selector.0, // Function selector.
        felt!(2_u8),                  // Calldata length.
        key,                          // Calldata: address.
        value                         // Calldata: value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata: calldata.clone(),
        ..trivial_external_entry_point
    };
    let call_info = entry_point_call.execute_directly(&mut state).unwrap();

    let expected_execution = CallExecution { retdata: retdata![value], ..Default::default() };
    let expected_inner_call_info = CallInfo {
        call: CallEntryPoint {
            class_hash: Some(test_contract.get_class_hash()),
            entry_point_selector: inner_entry_point_selector,
            calldata: inner_calldata,
            caller_address: test_address,
            ..trivial_external_entry_point
        },
        execution: expected_execution.clone(),
        resources: ExecutionResources {
            n_steps: 218,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::from([(BuiltinName::range_check, 2)]),
        },
        storage_read_values: vec![value],
        accessed_storage_keys: HashSet::from([storage_key!(key_int)]),
        ..Default::default()
    };
    let expected_call_info = CallInfo {
        inner_calls: vec![expected_inner_call_info],
        call: CallEntryPoint {
            class_hash: Some(test_contract.get_class_hash()),
            entry_point_selector: outer_entry_point_selector,
            calldata,
            ..trivial_external_entry_point
        },
        execution: expected_execution,
        resources: &get_syscall_resources(DeprecatedSyscallSelector::CallContract)
            + &ExecutionResources {
                n_steps: 257,
                n_memory_holes: 0,
                builtin_instance_counter: HashMap::from([(BuiltinName::range_check, 3)]),
            },
        ..Default::default()
    };

    assert_eq!(expected_call_info, call_info);
}

#[test]
fn test_replace_class() {
    // Negative flow.
    let chain_info = &ChainInfo::create_for_testing();
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let empty_contract = FeatureContract::Empty(CairoVersion::Cairo0);
    let mut state = test_state(chain_info, 0, &[(test_contract, 1), (empty_contract, 1)]);
    let test_address = test_contract.get_instance_address(0);
    // Replace with undeclared class hash.
    let calldata = calldata![felt!(1234_u16)];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point_new(test_contract)
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert!(error.contains("is not declared"));

    // Positive flow.
    let old_class_hash = test_contract.get_class_hash();
    let new_class_hash = empty_contract.get_class_hash();
    assert_eq!(state.get_class_hash_at(test_address).unwrap(), old_class_hash);
    let entry_point_call = CallEntryPoint {
        calldata: calldata![new_class_hash.0],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point_new(test_contract)
    };
    entry_point_call.execute_directly(&mut state).unwrap();
    assert_eq!(state.get_class_hash_at(test_address).unwrap(), new_class_hash);
}

#[rstest]
#[case::no_constructor(
    false, false, true, true, None
    // No constructor, trivial calldata, address available, deploy from zero; Positive flow.
)]
#[case::no_constructor_nonempty_calldata(
    false, true, true, true,
    Some(
        "Invalid input: constructor_calldata; Cannot pass calldata to a contract with no constructor.".to_string()
    )
    // No constructor, nontrivial calldata, address available, deploy from zero; Negative flow.
)]
#[case::with_constructor(
    true, true, true, true, None
    // With constructor, nontrivial calldata, address available, deploy from zero; Positive flow.
)]
#[case::deploy_to_unavailable_address(
    true, true, false, true,
    Some("is unavailable for deployment.".to_string())
    // With constructor, nontrivial calldata, address unavailable, deploy from zero; Negative flow.
)]
#[case::corrupt_deploy_from_zero(
    true, true, true, false,
    Some(format!(
        "Invalid syscall input: {:?}; {:}",
        felt!(2_u8),
        "The deploy_from_zero field in the deploy system call must be 0 or 1.",
    ))
    // With constructor, nontrivial calldata, address available, corrupt deploy from zero;
    // Negative flow.
)]
fn test_deploy(
    #[case] constructor_exists: bool,
    #[case] supply_constructor_calldata: bool,
    #[case] available_for_deployment: bool,
    #[case] valid_deploy_from_zero: bool,
    #[case] expected_error: Option<String>,
) {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let empty_contract = FeatureContract::Empty(CairoVersion::Cairo0);
    let mut state =
        test_state(&ChainInfo::create_for_testing(), 0, &[(empty_contract, 0), (test_contract, 1)]);

    let class_hash = if constructor_exists {
        test_contract.get_class_hash()
    } else {
        empty_contract.get_class_hash()
    };
    let constructor_calldata = if supply_constructor_calldata {
        vec![
            felt!(1_u8), // Calldata: address.
            felt!(1_u8), // Calldata: value.
        ]
    } else {
        vec![]
    };

    let calldata =
        calldata_for_deploy_test(class_hash, &constructor_calldata, valid_deploy_from_zero);

    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_deploy"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    if !available_for_deployment {
        // Deploy an instance of the contract for the scenario: deploy_to_unavailable_address.
        entry_point_call.clone().execute_directly(&mut state).unwrap();
    }

    if let Some(expected_error) = expected_error {
        let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
        assert!(error.contains(expected_error.as_str()));
        return;
    }

    // No errors expected.
    let contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &Calldata(constructor_calldata.into()),
        test_contract.get_instance_address(0),
    )
    .unwrap();
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![*contract_address.0.key()])
    );
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), class_hash);
}

#[test_case(
    ExecutionMode::Execute, "block_number", calldata![felt!(CURRENT_BLOCK_NUMBER)];
    "Test the syscall get_block_number in execution mode Execute")]
#[test_case(
    ExecutionMode::Validate, "block_number", calldata![felt!(CURRENT_BLOCK_NUMBER_FOR_VALIDATE)];
    "Test the syscall get_block_number in execution mode Validate")]
#[test_case(
    ExecutionMode::Execute, "block_timestamp", calldata![felt!(CURRENT_BLOCK_TIMESTAMP)];
    "Test the syscall get_block_timestamp in execution mode Execute")]
#[test_case(
    ExecutionMode::Validate, "block_timestamp", calldata![felt!(CURRENT_BLOCK_TIMESTAMP_FOR_VALIDATE)];
    "Test the syscall get_block_timestamp in execution mode Validate")]
#[test_case(
    ExecutionMode::Execute, "sequencer_address", calldata![felt!(TEST_SEQUENCER_ADDRESS)];
    "Test the syscall get_sequencer_address in execution mode Execute")]
#[test_case(
    ExecutionMode::Validate, "sequencer_address", calldata![felt!(0_u64)];
    "Test the syscall get_sequencer_address in execution mode Validate")]
fn test_block_info_syscalls(
    execution_mode: ExecutionMode,
    block_info_member_name: &str,
    calldata: Calldata,
) {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let entry_point_selector = selector_from_name(&format!("test_get_{}", block_info_member_name));
    let entry_point_call = CallEntryPoint {
        entry_point_selector,
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    if execution_mode == ExecutionMode::Validate {
        if block_info_member_name == "sequencer_address" {
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
                entry_point_call.execute_directly_in_validate_mode(&mut state).unwrap().execution,
                CallExecution::from_retdata(retdata![])
            );
        }
    } else {
        assert_eq!(
            entry_point_call.execute_directly(&mut state).unwrap().execution,
            CallExecution::from_retdata(retdata![])
        );
    }
}

#[rstest]
fn test_tx_info(#[values(false, true)] only_query: bool) {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let mut version = felt!(1_u8);
    if only_query {
        let simulate_version_base = Pow::pow(felt!(2_u8), QUERY_VERSION_BASE_BIT);
        version += simulate_version_base;
    }
    let tx_hash = TransactionHash(felt!(1991_u16));
    let max_fee = Fee(0);
    let nonce = nonce!(3_u16);
    let sender_address = test_contract.get_instance_address(0);
    let expected_tx_info = calldata![
        version,                                                     // Transaction version.
        *sender_address.0.key(),                                     // Account address.
        felt!(max_fee.0),                                            // Max fee.
        tx_hash.0,                                                   // Transaction hash.
        felt!(&*ChainId::Other(CHAIN_ID_NAME.to_string()).as_hex()), // Chain ID.
        nonce.0                                                      // Nonce.
    ];
    let entry_point_selector = selector_from_name("test_get_tx_info");
    let entry_point_call = CallEntryPoint {
        entry_point_selector,
        calldata: expected_tx_info,
        ..trivial_external_entry_point_new(test_contract)
    };
    let tx_info = TransactionInfo::Deprecated(DeprecatedTransactionInfo {
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
    let limit_steps_by_resources = true;
    let result = entry_point_call
        .execute_directly_given_tx_info(&mut state, tx_info, limit_steps_by_resources)
        .unwrap();

    assert!(!result.execution.failed)
}

#[test]
fn test_emit_event() {
    let versioned_constants = VersionedConstants::create_for_testing();
    // Positive flow.
    let keys = vec![felt!(2019_u16), felt!(2020_u16)];
    let data = vec![felt!(2021_u16), felt!(2022_u16), felt!(2023_u16)];
    let n_emitted_events = vec![felt!(1_u16)];
    let call_info = emit_events(&n_emitted_events, &keys, &data).unwrap();
    let event = EventContent {
        keys: keys.clone().into_iter().map(EventKey).collect(),
        data: EventData(data.clone()),
    };
    assert_eq!(
        call_info.execution,
        CallExecution {
            events: vec![OrderedEvent { order: 0, event }],
            gas_consumed: 0, // TODO why?
            ..Default::default()
        }
    );

    // Negative flow, the data length exceeds the limit.
    let max_event_data_length = versioned_constants.tx_event_limits.max_data_length;
    let data_too_long = vec![felt!(2_u16); max_event_data_length + 1];
    let error = emit_events(&n_emitted_events, &keys, &data_too_long).unwrap_err();
    let expected_error = EmitEventError::ExceedsMaxDataLength {
        data_length: max_event_data_length + 1,
        max_data_length: max_event_data_length,
    };
    assert!(error.to_string().contains(format!("{}", expected_error).as_str()));

    // Negative flow, the keys length exceeds the limit.
    let max_event_keys_length = versioned_constants.tx_event_limits.max_keys_length;
    let keys_too_long = vec![felt!(1_u16); max_event_keys_length + 1];
    let error = emit_events(&n_emitted_events, &keys_too_long, &data).unwrap_err();
    let expected_error = EmitEventError::ExceedsMaxKeysLength {
        keys_length: max_event_keys_length + 1,
        max_keys_length: max_event_keys_length,
    };
    assert!(error.to_string().contains(format!("{}", expected_error).as_str()));

    // Negative flow, the number of events exceeds the limit.
    let max_n_emitted_events = versioned_constants.tx_event_limits.max_n_emitted_events;
    let n_emitted_events_too_big = vec![felt!(
        u16::try_from(max_n_emitted_events + 1).expect("Failed to convert usize to u16.")
    )];
    let error = emit_events(&n_emitted_events_too_big, &keys, &data).unwrap_err();
    let expected_error = EmitEventError::ExceedsMaxNumberOfEmittedEvents {
        n_emitted_events: max_n_emitted_events + 1,
        max_n_emitted_events,
    };
    assert!(error.to_string().contains(format!("{}", expected_error).as_str()));
}

fn emit_events(
    n_emitted_events: &[Felt],
    keys: &[Felt],
    data: &[Felt],
) -> Result<CallInfo, EntryPointExecutionError> {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut state = test_state(&ChainInfo::create_for_testing(), 0, &[(test_contract, 1)]);
    let calldata = Calldata(
        [
            n_emitted_events.to_owned(),
            vec![felt!(u16::try_from(keys.len()).expect("Failed to convert usize to u16."))],
            keys.to_vec(),
            vec![felt!(u16::try_from(data.len()).expect("Failed to convert usize to u16."))],
            data.to_vec(),
        ]
        .concat()
        .into(),
    );

    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_emit_events"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    entry_point_call.execute_directly(&mut state)
}
