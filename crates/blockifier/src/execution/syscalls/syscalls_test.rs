use std::collections::{BTreeMap, HashMap, HashSet};

use assert_matches::assert_matches;
use cairo_lang_utils::byte_array::BYTE_ARRAY_MAGIC;
use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use num_traits::Pow;
use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::core::{
    calculate_contract_address, ChainId, ContractAddress, EthAddress, PatriciaKey,
};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    AccountDeploymentData, Calldata, ContractAddressSalt, EventContent, EventData, EventKey, Fee,
    L2ToL1Payload, PaymasterData, Resource, ResourceBounds, ResourceBoundsMapping, Tip,
    TransactionHash, TransactionVersion,
};
use starknet_api::{calldata, felt};
use starknet_types_core::felt::Felt;
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants;
use crate::context::ChainInfo;
use crate::execution::call_info::{
    CallExecution, CallInfo, MessageToL1, OrderedEvent, OrderedL2ToL1Message, Retdata,
};
use crate::execution::common_hints::ExecutionMode;
use crate::execution::entry_point::{CallEntryPoint, CallType};
use crate::execution::errors::EntryPointExecutionError;
use crate::execution::syscalls::hint_processor::{
    EmitEventError, BLOCK_NUMBER_OUT_OF_RANGE_ERROR, L1_GAS, L2_GAS, OUT_OF_GAS_ERROR,
};
use crate::execution::syscalls::SyscallSelector;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{
    calldata_for_deploy_test, create_calldata, get_syscall_resources,
    trivial_external_entry_point_new, trivial_external_entry_point_with_address, CairoVersion,
    BALANCE, CHAIN_ID_NAME, CURRENT_BLOCK_NUMBER, CURRENT_BLOCK_NUMBER_FOR_VALIDATE,
    CURRENT_BLOCK_TIMESTAMP, CURRENT_BLOCK_TIMESTAMP_FOR_VALIDATE, TEST_SEQUENCER_ADDRESS,
};
use crate::transaction::constants::QUERY_VERSION_BASE_BIT;
use crate::transaction::objects::{
    CommonAccountFields, CurrentTransactionInfo, DeprecatedTransactionInfo, TransactionInfo,
};
use crate::versioned_constants::VersionedConstants;
use crate::{check_entry_point_execution_error_for_custom_hint, nonce, retdata, storage_key};
pub const REQUIRED_GAS_STORAGE_READ_WRITE_TEST: u64 = 27150;
pub const REQUIRED_GAS_CALL_CONTRACT_TEST: u64 = 105680;
pub const REQUIRED_GAS_LIBRARY_CALL_TEST: u64 = REQUIRED_GAS_CALL_CONTRACT_TEST;

#[test]
fn test_storage_read_write() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

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
        CallExecution {
            retdata: retdata![value],
            gas_consumed: REQUIRED_GAS_STORAGE_READ_WRITE_TEST,
            ..CallExecution::default()
        }
    );
    // Verify that the state has changed.
    let value_from_state =
        state.get_storage_at(storage_address, StorageKey::try_from(key).unwrap()).unwrap();
    assert_eq!(value_from_state, value);
}

#[test]
fn test_call_contract() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let outer_entry_point_selector = selector_from_name("test_call_contract");
    let calldata = create_calldata(
        FeatureContract::TestContract(CairoVersion::Cairo1).get_instance_address(0),
        "test_storage_read_write",
        &[
            felt!(405_u16), // Calldata: address.
            felt!(48_u8),   // Calldata: value.
        ],
    );
    let entry_point_call = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            retdata: retdata![felt!(48_u8)],
            gas_consumed: REQUIRED_GAS_CALL_CONTRACT_TEST,
            ..CallExecution::default()
        }
    );
}

#[test]
fn test_emit_event() {
    let versioned_constants = VersionedConstants::create_for_testing();
    // Positive flow.
    let keys = vec![felt!(2019_u16), felt!(2020_u16)];
    let data = vec![felt!(2021_u16), felt!(2022_u16), felt!(2023_u16)];
    // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion works.
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
            gas_consumed: 49860,
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
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);
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

#[test]
fn test_get_block_hash() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    // Initialize block number -> block hash entry.
    let upper_bound_block_number = CURRENT_BLOCK_NUMBER - constants::STORED_BLOCK_HASH_BUFFER;
    let block_number = felt!(upper_bound_block_number);
    let block_hash = felt!(66_u64);
    let key = StorageKey::try_from(block_number).unwrap();
    let block_hash_contract_address =
        ContractAddress::try_from(Felt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS)).unwrap();
    state.set_storage_at(block_hash_contract_address, key, block_hash).unwrap();

    // Positive flow.
    let calldata = calldata![block_number];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_get_block_hash"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    assert_eq!(
        entry_point_call.clone().execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed: 9680, ..CallExecution::from_retdata(retdata![block_hash]) }
    );

    // Negative flow. Execution mode is Validate.
    let error = entry_point_call.execute_directly_in_validate_mode(&mut state).unwrap_err();
    check_entry_point_execution_error_for_custom_hint!(
        &error,
        "Unauthorized syscall get_block_hash in execution mode Validate.",
    );

    // Negative flow: Block number out of range.
    let requested_block_number = CURRENT_BLOCK_NUMBER - constants::STORED_BLOCK_HASH_BUFFER + 1;
    let block_number = felt!(requested_block_number);
    let calldata = calldata![block_number];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_get_block_hash"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err();
    assert_matches!(error, EntryPointExecutionError::ExecutionFailed{ error_data }
        if error_data == vec![felt!(BLOCK_NUMBER_OUT_OF_RANGE_ERROR)]);
}

#[test]
fn test_keccak() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let calldata = Calldata(vec![].into());
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_keccak"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed: 256250, ..CallExecution::from_retdata(retdata![]) }
    );
}

#[test]
fn test_sha256() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let calldata = Calldata(vec![].into());
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_sha256"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed: 892990, ..CallExecution::from_retdata(retdata![]) }
    );
}

fn verify_compiler_version(contract: FeatureContract, expected_version: &str) {
    // Read and parse file content.
    let raw_contract: serde_json::Value =
        serde_json::from_str(&contract.get_raw_class()).expect("Error parsing JSON");

    // Verify version.
    if let Some(compiler_version) = raw_contract["compiler_version"].as_str() {
        assert_eq!(compiler_version, expected_version);
    } else {
        panic!("'compiler_version' not found or not a valid string in JSON.");
    }
}

#[test_case(
    ExecutionMode::Validate,
    TransactionVersion::ONE,
    false,
    false;
    "Validate execution mode: block info fields should be zeroed. Transaction V1.")]
#[test_case(
    ExecutionMode::Execute,
    TransactionVersion::ONE,
    false,
    false;
    "Execute execution mode: block info should be as usual. Transaction V1.")]
#[test_case(
    ExecutionMode::Validate,
    TransactionVersion::THREE,
    false,
    false;
    "Validate execution mode: block info fields should be zeroed. Transaction V3.")]
#[test_case(
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    false,
    false;
    "Execute execution mode: block info should be as usual. Transaction V3.")]
#[test_case(
    ExecutionMode::Execute,
    TransactionVersion::ONE,
    true,
    false;
    "Legacy contract. Execute execution mode: block info should be as usual. Transaction V1.")]
#[test_case(
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    true,
    false;
    "Legacy contract. Execute execution mode: block info should be as usual. Transaction V3.")]
#[test_case(
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    false,
    true;
    "Execute execution mode: block info should be as usual. Transaction V3. Query.")]
fn test_get_execution_info(
    execution_mode: ExecutionMode,
    mut version: TransactionVersion,
    is_legacy: bool,
    only_query: bool,
) {
    let legacy_contract = FeatureContract::LegacyTestContract;
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let state = &mut test_state(
        &ChainInfo::create_for_testing(),
        BALANCE,
        &[(legacy_contract, 1), (test_contract, 1)],
    );
    let expected_block_info = match execution_mode {
        ExecutionMode::Validate => [
            // Rounded block number.
            felt!(CURRENT_BLOCK_NUMBER_FOR_VALIDATE),
            // Rounded timestamp.
            felt!(CURRENT_BLOCK_TIMESTAMP_FOR_VALIDATE),
            Felt::ZERO,
        ],
        ExecutionMode::Execute => [
            felt!(CURRENT_BLOCK_NUMBER),    // Block number.
            felt!(CURRENT_BLOCK_TIMESTAMP), // Block timestamp.
            Felt::from_hex(TEST_SEQUENCER_ADDRESS).unwrap(),
        ],
    };

    let (test_contract_address, expected_unsupported_fields) = if is_legacy {
        verify_compiler_version(legacy_contract, "2.1.0");
        (legacy_contract.get_instance_address(0), vec![])
    } else {
        (
            test_contract.get_instance_address(0),
            vec![
                Felt::ZERO, // Tip.
                Felt::ZERO, // Paymaster data.
                Felt::ZERO, // Nonce DA.
                Felt::ZERO, // Fee DA.
                Felt::ZERO, // Account data.
            ],
        )
    };

    if only_query {
        let simulate_version_base = Pow::pow(Felt::from(2_u8), QUERY_VERSION_BASE_BIT);
        let query_version = simulate_version_base + version.0;
        version = TransactionVersion(query_version);
    }

    let tx_hash = TransactionHash(felt!(1991_u16));
    let max_fee = Fee(42);
    let nonce = nonce!(3_u16);
    let sender_address = test_contract_address;

    let expected_tx_info: Vec<Felt>;
    let mut expected_resource_bounds: Vec<Felt> = vec![];
    let tx_info: TransactionInfo;
    if version == TransactionVersion::ONE {
        expected_tx_info = vec![
            version.0,                                                   // Transaction version.
            *sender_address.0.key(),                                     // Account address.
            felt!(max_fee.0),                                            // Max fee.
            Felt::ZERO,                                                  // Signature.
            tx_hash.0,                                                   // Transaction hash.
            felt!(&*ChainId::Other(CHAIN_ID_NAME.to_string()).as_hex()), // Chain ID.
            nonce.0,                                                     // Nonce.
        ];
        if !is_legacy {
            expected_resource_bounds = vec![
                felt!(0_u16), // Length of resource bounds array.
            ];
        }
        tx_info = TransactionInfo::Deprecated(DeprecatedTransactionInfo {
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
    } else {
        let max_amount = Fee(13);
        let max_price_per_unit = Fee(61);
        expected_tx_info = vec![
            version.0,                                                   // Transaction version.
            *sender_address.0.key(),                                     // Account address.
            Felt::ZERO,                                                  // Max fee.
            Felt::ZERO,                                                  // Signature.
            tx_hash.0,                                                   // Transaction hash.
            felt!(&*ChainId::Other(CHAIN_ID_NAME.to_string()).as_hex()), // Chain ID.
            nonce.0,                                                     // Nonce.
        ];
        if !is_legacy {
            expected_resource_bounds = vec![
                Felt::from(2u32),            // Length of ResourceBounds array.
                felt!(L1_GAS),               // Resource.
                felt!(max_amount.0),         // Max amount.
                felt!(max_price_per_unit.0), // Max price per unit.
                felt!(L2_GAS),               // Resource.
                Felt::ZERO,                  // Max amount.
                Felt::ZERO,                  // Max price per unit.
            ];
        }
        tx_info = TransactionInfo::Current(CurrentTransactionInfo {
            common_fields: CommonAccountFields {
                transaction_hash: tx_hash,
                version: TransactionVersion::THREE,
                nonce,
                sender_address,
                only_query,
                ..Default::default()
            },
            resource_bounds: ResourceBoundsMapping(BTreeMap::from([
                (
                    Resource::L1Gas,
                    // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the
                    // convertion works.
                    ResourceBounds {
                        max_amount: max_amount
                            .0
                            .try_into()
                            .expect("Failed to convert u128 to u64."),
                        max_price_per_unit: max_price_per_unit.0,
                    },
                ),
                (Resource::L2Gas, ResourceBounds { max_amount: 0, max_price_per_unit: 0 }),
            ])),
            tip: Tip::default(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            paymaster_data: PaymasterData::default(),
            account_deployment_data: AccountDeploymentData::default(),
        });
    }

    let entry_point_selector = selector_from_name("test_get_execution_info");
    let expected_call_info = vec![
        felt!(0_u16),                   // Caller address.
        *test_contract_address.0.key(), // Storage address.
        entry_point_selector.0,         // Entry point selector.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector,
        code_address: None,
        calldata: Calldata(
            [
                expected_block_info.to_vec(),
                expected_tx_info,
                expected_resource_bounds,
                expected_unsupported_fields,
                expected_call_info,
            ]
            .concat()
            .into(),
        ),
        ..trivial_external_entry_point_with_address(test_contract_address)
    };

    let result = match execution_mode {
        ExecutionMode::Validate => {
            entry_point_call.execute_directly_given_tx_info_in_validate_mode(state, tx_info, false)
        }
        ExecutionMode::Execute => {
            entry_point_call.execute_directly_given_tx_info(state, tx_info, false)
        }
    };

    assert!(!result.unwrap().execution.failed);
}

#[test]
fn test_library_call() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let calldata = calldata![
        test_contract.get_class_hash().0, // Class hash.
        inner_entry_point_selector.0,     // Function selector.
        felt!(2_u8),                      // Calldata length.
        felt!(1234_u16),                  // Calldata: address.
        felt!(91_u8)                      // Calldata: value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_library_call"),
        calldata,
        class_hash: Some(test_contract.get_class_hash()),
        ..trivial_external_entry_point_new(test_contract)
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            retdata: retdata![felt!(91_u16)],
            gas_consumed: REQUIRED_GAS_LIBRARY_CALL_TEST,
            ..Default::default()
        }
    );
}

#[test]
fn test_library_call_assert_fails() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);
    let inner_entry_point_selector = selector_from_name("assert_eq");
    let calldata = calldata![
        test_contract.get_class_hash().0, // Class hash.
        inner_entry_point_selector.0,     // Function selector.
        felt!(2_u8),                      // Calldata length.
        felt!(0_u8),                      // Calldata: first assert value.
        felt!(1_u8)                       // Calldata: second assert value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_library_call"),
        calldata,
        class_hash: Some(test_contract.get_class_hash()),
        ..trivial_external_entry_point_new(test_contract)
    };

    assert!(
        entry_point_call.execute_directly(&mut state).unwrap_err().to_string().contains("x != y")
    );
}

#[test]
fn test_nested_library_call() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let (key, value) = (255_u64, 44_u64);
    let outer_entry_point_selector = selector_from_name("test_library_call");
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let test_class_hash = test_contract.get_class_hash();
    let main_entry_point_calldata = calldata![
        test_class_hash.0,            // Class hash.
        outer_entry_point_selector.0, // Library call function selector.
        inner_entry_point_selector.0, // Storage function selector.
        felt!(key),                   // Calldata: address.
        felt!(value)                  // Calldata: value.
    ];

    // Create expected call info tree.
    let main_entry_point = CallEntryPoint {
        entry_point_selector: selector_from_name("test_nested_library_call"),
        calldata: main_entry_point_calldata,
        class_hash: Some(test_class_hash),
        initial_gas: 9999906600,
        ..trivial_external_entry_point_new(test_contract)
    };
    let nested_storage_entry_point = CallEntryPoint {
        entry_point_selector: inner_entry_point_selector,
        calldata: calldata![felt!(key + 1), felt!(value + 1)],
        class_hash: Some(test_class_hash),
        code_address: None,
        call_type: CallType::Delegate,
        initial_gas: 9999745020,
        ..trivial_external_entry_point_new(test_contract)
    };
    let library_entry_point = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata: calldata![
            test_class_hash.0,            // Class hash.
            inner_entry_point_selector.0, // Storage function selector.
            felt!(2_u8),                  // Calldata: address.
            felt!(key + 1),               // Calldata: address.
            felt!(value + 1)              // Calldata: value.
        ],
        class_hash: Some(test_class_hash),
        code_address: None,
        call_type: CallType::Delegate,
        initial_gas: 9999823550,
        ..trivial_external_entry_point_new(test_contract)
    };
    let storage_entry_point = CallEntryPoint {
        calldata: calldata![felt!(key), felt!(value)],
        initial_gas: 9999656870,
        ..nested_storage_entry_point
    };
    let storage_entry_point_resources = ExecutionResources {
        n_steps: 243,
        n_memory_holes: 0,
        builtin_instance_counter: HashMap::from([(BuiltinName::range_check, 7)]),
    };
    let nested_storage_call_info = CallInfo {
        call: nested_storage_entry_point,
        execution: CallExecution {
            retdata: retdata![felt!(value + 1)],
            gas_consumed: REQUIRED_GAS_STORAGE_READ_WRITE_TEST,
            ..CallExecution::default()
        },
        resources: storage_entry_point_resources.clone(),
        storage_read_values: vec![felt!(value + 1)],
        accessed_storage_keys: HashSet::from([storage_key!(key + 1)]),
        ..Default::default()
    };
    let library_call_resources = &get_syscall_resources(SyscallSelector::LibraryCall)
        + &ExecutionResources {
            n_steps: 388,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::from([(BuiltinName::range_check, 15)]),
        };
    let library_call_info = CallInfo {
        call: library_entry_point,
        execution: CallExecution {
            retdata: retdata![felt!(value + 1)],
            gas_consumed: REQUIRED_GAS_LIBRARY_CALL_TEST,
            ..CallExecution::default()
        },
        resources: library_call_resources,
        inner_calls: vec![nested_storage_call_info],
        ..Default::default()
    };
    let storage_call_info = CallInfo {
        call: storage_entry_point,
        execution: CallExecution {
            retdata: retdata![felt!(value)],
            gas_consumed: REQUIRED_GAS_STORAGE_READ_WRITE_TEST,
            ..CallExecution::default()
        },
        resources: storage_entry_point_resources,
        storage_read_values: vec![felt!(value)],
        accessed_storage_keys: HashSet::from([storage_key!(key)]),
        ..Default::default()
    };

    let main_call_resources = &(&get_syscall_resources(SyscallSelector::LibraryCall) * 3)
        + &ExecutionResources {
            n_steps: 749,
            n_memory_holes: 2,
            builtin_instance_counter: HashMap::from([(BuiltinName::range_check, 27)]),
        };
    let expected_call_info = CallInfo {
        call: main_entry_point.clone(),
        execution: CallExecution {
            retdata: retdata![felt!(value)],
            gas_consumed: 276880,
            ..CallExecution::default()
        },
        resources: main_call_resources,
        inner_calls: vec![library_call_info, storage_call_info],
        ..Default::default()
    };

    assert_eq!(main_entry_point.execute_directly(&mut state).unwrap(), expected_call_info);
}

#[test]
fn test_replace_class() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let empty_contract = FeatureContract::Empty(CairoVersion::Cairo1);
    let empty_contract_cairo0 = FeatureContract::Empty(CairoVersion::Cairo0);
    let mut state = test_state(
        &ChainInfo::create_for_testing(),
        BALANCE,
        &[(test_contract, 1), (empty_contract, 0), (empty_contract_cairo0, 0)],
    );
    let contract_address = test_contract.get_instance_address(0);

    // Negative flow.

    // Replace with undeclared class hash.
    let entry_point_call = CallEntryPoint {
        calldata: calldata![felt!(1234_u16)],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point_new(test_contract)
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert!(error.contains("is not declared"));

    // Replace with Cairo 0 class hash.
    let v0_class_hash = empty_contract_cairo0.get_class_hash();

    let entry_point_call = CallEntryPoint {
        calldata: calldata![v0_class_hash.0],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point_new(test_contract)
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert!(error.contains("Cannot replace V1 class hash with V0 class hash"));

    // Positive flow.
    let old_class_hash = test_contract.get_class_hash();
    let new_class_hash = empty_contract.get_class_hash();
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), old_class_hash);
    let entry_point_call = CallEntryPoint {
        calldata: calldata![new_class_hash.0],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point_new(test_contract)
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed: 9750, ..Default::default() }
    );
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), new_class_hash);
}

#[test]
fn test_secp256k1() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let calldata = Calldata(vec![].into());
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_secp256k1"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed: 17033810_u64, ..Default::default() }
    );
}

#[test]
fn test_secp256r1() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let calldata = Calldata(vec![].into());
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_secp256r1"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed: 27582260_u64, ..Default::default() }
    );
}

#[test]
fn test_send_message_to_l1() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let to_address = felt!(1234_u16);
    let payload = vec![felt!(2019_u16), felt!(2020_u16), felt!(2021_u16)];
    let calldata = Calldata(
        [
            vec![
                to_address,
                // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the
                // convertion works.
                felt!(u64::try_from(payload.len()).expect("Failed to convert usize to u64.")),
            ],
            payload.clone(),
        ]
        .concat()
        .into(),
    );
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_send_message_to_l1"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    let to_address = EthAddress::try_from(to_address).unwrap();
    let message = MessageToL1 { to_address, payload: L2ToL1Payload(payload) };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            l2_to_l1_messages: vec![OrderedL2ToL1Message { order: 0, message }],
            gas_consumed: 22990,
            ..Default::default()
        }
    );
}

#[rstest]
#[case::no_constructor(
    false, false, true, None
    // No constructor, trivial calldata, address available; Positive flow.
)]
#[case::no_constructor_nonempty_calldata(
    false, true, true,
    Some(
        "Invalid input: constructor_calldata; Cannot pass calldata to a contract with no constructor.".to_string()
    )
    // No constructor, nontrivial calldata, address available; Negative flow.
)]
#[case::with_constructor(
    true, true, true, None
    // With constructor, nontrivial calldata, address available; Positive flow.
)]
#[case::deploy_to_unavailable_address(
    true, true, false,
    Some("is unavailable for deployment.".to_string())
    // With constructor, nontrivial calldata, address unavailable; Negative flow.
)]
fn test_deploy(
    #[case] constructor_exists: bool,
    #[case] supply_constructor_calldata: bool,
    #[case] available_for_deployment: bool,
    #[case] expected_error: Option<String>,
) {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let empty_contract = FeatureContract::Empty(CairoVersion::Cairo1);
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

    let calldata = calldata_for_deploy_test(class_hash, &constructor_calldata, true);

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
        &Calldata(constructor_calldata.clone().into()),
        test_contract.get_instance_address(0),
    )
    .unwrap();
    let deploy_call = &entry_point_call.execute_directly(&mut state).unwrap().inner_calls[0];
    assert_eq!(deploy_call.call.storage_address, contract_address);
    let mut retdata = retdata![];
    let gas_consumed = if constructor_calldata.is_empty() {
        0
    } else {
        retdata.0.push(constructor_calldata[0]);
        10140
    };
    assert_eq!(
        deploy_call.execution,
        CallExecution { retdata, gas_consumed, ..CallExecution::default() }
    );
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), class_hash);
}

#[test]
fn test_out_of_gas() {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let key = felt!(1234_u16);
    let value = felt!(18_u8);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        initial_gas: REQUIRED_GAS_STORAGE_READ_WRITE_TEST - 1,
        ..trivial_external_entry_point_new(test_contract)
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err();
    assert_matches!(error, EntryPointExecutionError::ExecutionFailed{ error_data }
        if error_data == vec![felt!(OUT_OF_GAS_ERROR)]);
}

#[test]
fn test_syscall_failure_format() {
    let error_data = vec![
        // Magic to indicate that this is a byte array.
        BYTE_ARRAY_MAGIC,
        // the number of full words in the byte array.
        "0x00",
        // The pending word of the byte array: "Execution failure"
        "0x457865637574696f6e206661696c757265",
        // The length of the pending word.
        "0x11",
    ]
    .into_iter()
    .map(|x| Felt::from_hex(x).unwrap())
    .collect();
    let error = EntryPointExecutionError::ExecutionFailed { error_data };
    assert_eq!(error.to_string(), "Execution failed. Failure reason: \"Execution failure\".");
}
