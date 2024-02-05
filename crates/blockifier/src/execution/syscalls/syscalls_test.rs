use std::collections::{BTreeMap, HashMap, HashSet};

use assert_matches::assert_matches;
use cairo_lang_utils::byte_array::BYTE_ARRAY_MAGIC;
use cairo_vm::vm::runners::builtin_runner::RANGE_CHECK_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use itertools::concat;
use num_traits::Pow;
use pretty_assertions::assert_eq;
use starknet_api::core::{
    calculate_contract_address, ChainId, ClassHash, ContractAddress, EthAddress, Nonce, PatriciaKey,
};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    AccountDeploymentData, Calldata, ContractAddressSalt, EventContent, EventData, EventKey, Fee,
    L2ToL1Payload, PaymasterData, Resource, ResourceBounds, ResourceBoundsMapping, Tip,
    TransactionHash, TransactionVersion,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key};
use starknet_types_core::felt::Felt;
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants;
use crate::block_context::ChainInfo;
use crate::execution::call_info::{
    CallExecution, CallInfo, MessageToL1, OrderedEvent, OrderedL2ToL1Message, Retdata,
};
use crate::execution::common_hints::ExecutionMode;
use crate::execution::contract_class::ContractClassV0;
use crate::execution::entry_point::{CallEntryPoint, CallType};
use crate::execution::errors::{EntryPointExecutionError, VirtualMachineExecutionError};
use crate::execution::syscalls::hint_processor::{
    BLOCK_NUMBER_OUT_OF_RANGE_ERROR, L1_GAS, L2_GAS, OUT_OF_GAS_ERROR,
};
use crate::state::state_api::{State, StateReader};
use crate::test_utils::cached_state::{create_deploy_test_state, create_test_state};
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{
    create_calldata, trivial_external_entry_point, CairoVersion, BALANCE, CHAIN_ID_NAME,
    CURRENT_BLOCK_NUMBER, CURRENT_BLOCK_TIMESTAMP, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS,
    TEST_EMPTY_CONTRACT_CAIRO0_PATH, TEST_EMPTY_CONTRACT_CLASS_HASH, TEST_SEQUENCER_ADDRESS,
};
use crate::transaction::constants::QUERY_VERSION_BASE_BIT;
use crate::transaction::objects::{
    AccountTransactionContext, CommonAccountFields, CurrentAccountTransactionContext,
    DeprecatedAccountTransactionContext,
};
use crate::{check_entry_point_execution_error_for_custom_hint, retdata};

pub const REQUIRED_GAS_STORAGE_READ_WRITE_TEST: u64 = 34650;
pub const REQUIRED_GAS_CALL_CONTRACT_TEST: u64 = 128080;
pub const REQUIRED_GAS_LIBRARY_CALL_TEST: u64 = REQUIRED_GAS_CALL_CONTRACT_TEST;

#[test]
fn test_storage_read_write() {
    let mut state = create_test_state();

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
    let mut state = create_test_state();

    let outer_entry_point_selector = selector_from_name("test_call_contract");
    let calldata = create_calldata(
        contract_address!(TEST_CONTRACT_ADDRESS),
        "test_storage_read_write",
        &[
            Felt::from(405_u16), // Calldata: address.
            Felt::from(48_u8),   // Calldata: value.
        ],
    );
    let entry_point_call = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata,
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            retdata: retdata![Felt::from(48_u8)],
            gas_consumed: REQUIRED_GAS_CALL_CONTRACT_TEST,
            ..CallExecution::default()
        }
    );
}

#[test]
fn test_emit_event() {
    let mut state = create_test_state();

    let keys = vec![Felt::from(2019_u16), Felt::from(2020_u16)];
    let data = vec![Felt::from(2021_u16), Felt::from(2022_u16), Felt::from(2023_u16)];
    // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion works.
    let calldata = Calldata(
        concat(vec![
            vec![Felt::from(u8::try_from(keys.len()).expect("Failed to convert usize to u8."))],
            keys.clone(),
            vec![Felt::from(u8::try_from(data.len()).expect("Failed to convert usize to u8."))],
            data.clone(),
        ])
        .into(),
    );
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_emit_event"),
        calldata,
        ..trivial_external_entry_point()
    };

    let event =
        EventContent { keys: keys.into_iter().map(EventKey).collect(), data: EventData(data) };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            events: vec![OrderedEvent { order: 0, event }],
            gas_consumed: 52570,
            ..Default::default()
        }
    );
}

#[test]
fn test_get_block_hash() {
    let mut state = create_test_state();

    // Initialize block number -> block hash entry.
    let upper_bound_block_number = CURRENT_BLOCK_NUMBER - constants::STORED_BLOCK_HASH_BUFFER;
    let block_number = Felt::from(upper_bound_block_number);
    let block_hash = Felt::from(66_u64);
    let key = StorageKey::try_from(block_number).unwrap();
    let block_hash_contract_address =
        ContractAddress::try_from(Felt::from_hex_unchecked(constants::BLOCK_HASH_CONTRACT_ADDRESS))
            .unwrap();
    state.set_storage_at(block_hash_contract_address, key, block_hash).unwrap();

    // Positive flow.
    let calldata = calldata![block_number];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_get_block_hash"),
        calldata,
        ..trivial_external_entry_point()
    };

    assert_eq!(
        entry_point_call.clone().execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed: 14250, ..CallExecution::from_retdata(retdata![block_hash]) }
    );

    // Negative flow. Execution mode is Validate.
    let error = entry_point_call.execute_directly_in_validate_mode(&mut state).unwrap_err();
    check_entry_point_execution_error_for_custom_hint!(
        &error,
        "Unauthorized syscall get_block_hash in execution mode Validate.",
    );

    // Negative flow: Block number out of range.
    let requested_block_number = CURRENT_BLOCK_NUMBER - constants::STORED_BLOCK_HASH_BUFFER + 1;
    let block_number = Felt::from(requested_block_number);
    let calldata = calldata![block_number];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_get_block_hash"),
        calldata,
        ..trivial_external_entry_point()
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err();
    assert_matches!(error, EntryPointExecutionError::ExecutionFailed{ error_data }
        if error_data == vec![Felt::from_raw_const(BLOCK_NUMBER_OUT_OF_RANGE_ERROR)]);
}

#[test]
fn test_keccak() {
    let mut state = create_test_state();

    let calldata = Calldata(vec![].into());
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_keccak"),
        calldata,
        ..trivial_external_entry_point()
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed: 354940, ..CallExecution::from_retdata(retdata![]) }
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
    contract_address!(Felt::ZERO),
    TransactionVersion::ONE,
    false,
    false;
    "Validate execution mode: block info fields should be zeroed. Transaction V1.")]
#[test_case(
    ExecutionMode::Execute,
    contract_address!(TEST_SEQUENCER_ADDRESS),
    TransactionVersion::ONE,
    false,
    false;
    "Execute execution mode: block info should be as usual. Transaction V1.")]
#[test_case(
    ExecutionMode::Validate,
    contract_address!(Felt::ZERO),
    TransactionVersion::THREE,
    false,
    false;
    "Validate execution mode: block info fields should be zeroed. Transaction V3.")]
#[test_case(
    ExecutionMode::Execute,
    contract_address!(TEST_SEQUENCER_ADDRESS),
    TransactionVersion::THREE,
    false,
    false;
    "Execute execution mode: block info should be as usual. Transaction V3.")]
#[test_case(
    ExecutionMode::Execute,
    contract_address!(TEST_SEQUENCER_ADDRESS),
    TransactionVersion::ONE,
    true,
    false;
    "Legacy contract. Execute execution mode: block info should be as usual. Transaction V1.")]
#[test_case(
    ExecutionMode::Execute,
    contract_address!(TEST_SEQUENCER_ADDRESS),
    TransactionVersion::THREE,
    true,
    false;
    "Legacy contract. Execute execution mode: block info should be as usual. Transaction V3.")]
#[test_case(
    ExecutionMode::Execute,
    contract_address!(TEST_SEQUENCER_ADDRESS),
    TransactionVersion::THREE,
    false,
    true;
    "Execute execution mode: block info should be as usual. Transaction V3. Query.")]
fn test_get_execution_info(
    execution_mode: ExecutionMode,
    sequencer_address: ContractAddress,
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
    let expected_block_info = [
        Felt::from(CURRENT_BLOCK_NUMBER),    // Block number.
        Felt::from(CURRENT_BLOCK_TIMESTAMP), // Block timestamp.
        sequencer_address.0.to_felt(),
    ];

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
        let simulate_version_base = Pow::pow(Felt::TWO, QUERY_VERSION_BASE_BIT);
        let query_version = simulate_version_base + version.0;
        version = TransactionVersion(query_version);
    }

    let tx_hash = TransactionHash(Felt::from(1991_u16));
    let max_fee = Fee(42);
    let nonce = Nonce(Felt::from(3_u16));
    let sender_address = test_contract_address;

    let expected_tx_info: Vec<Felt>;
    let mut expected_resource_bounds: Vec<Felt> = vec![];
    let account_tx_context: AccountTransactionContext;
    if version == TransactionVersion::ONE {
        expected_tx_info = vec![
            version.0,                  // Transaction version.
            sender_address.0.to_felt(), // Account address.
            Felt::from(max_fee.0),      // Max fee.
            Felt::ZERO,                 // Signature.
            tx_hash.0,                  // Transaction hash.
            Felt::from_hex(&ChainId(CHAIN_ID_NAME.to_string()).as_hex()).unwrap(), // Chain ID.
            nonce.0,                    // Nonce.
        ];
        if !is_legacy {
            expected_resource_bounds = vec![
                Felt::ZERO, // Length of resource bounds array.
            ];
        }
        account_tx_context =
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
    } else {
        let max_amount = Fee(13);
        let max_price_per_unit = Fee(61);
        expected_tx_info = vec![
            version.0,                  // Transaction version.
            sender_address.0.to_felt(), // Account address.
            Felt::ZERO,                 // Max fee.
            Felt::ZERO,                 // Signature.
            tx_hash.0,                  // Transaction hash.
            Felt::from_hex(&ChainId(CHAIN_ID_NAME.to_string()).as_hex()).unwrap(), // Chain ID.
            nonce.0,                    // Nonce.
        ];
        if !is_legacy {
            expected_resource_bounds = vec![
                Felt::TWO,                        // Length of ResourceBounds array.
                Felt::from_raw_const(L1_GAS),     // Resource.
                Felt::from(max_amount.0),         // Max amount.
                Felt::from(max_price_per_unit.0), // Max price per unit.
                Felt::from_raw_const(L2_GAS),     // Resource.
                Felt::ZERO,                       // Max amount.
                Felt::ZERO,                       // Max price per unit.
            ];
        }
        account_tx_context = AccountTransactionContext::Current(CurrentAccountTransactionContext {
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
        Felt::ZERO,                        // Caller address.
        test_contract_address.0.to_felt(), // Storage address.
        entry_point_selector.0,            // Entry point selector.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector,
        storage_address: test_contract_address,
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
        ..trivial_external_entry_point()
    };

    let result = match execution_mode {
        ExecutionMode::Validate => entry_point_call
            .execute_directly_given_account_context_in_validate_mode(
                state,
                account_tx_context,
                false,
            ),
        ExecutionMode::Execute => entry_point_call.execute_directly_given_account_context(
            state,
            account_tx_context,
            false,
        ),
    };

    assert!(!result.unwrap().execution.failed);
}

#[test]
fn test_library_call() {
    let mut state = create_test_state();

    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let calldata = calldata![
        Felt::from(TEST_CLASS_HASH),  // Class hash.
        inner_entry_point_selector.0, // Function selector.
        Felt::TWO,                    // Calldata length.
        Felt::from(1234_u16),         // Calldata: address.
        Felt::from(91_u8)             // Calldata: value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_library_call"),
        calldata,
        class_hash: Some(class_hash!(TEST_CLASS_HASH)),
        ..trivial_external_entry_point()
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            retdata: retdata![Felt::from(91_u16)],
            gas_consumed: REQUIRED_GAS_LIBRARY_CALL_TEST,
            ..Default::default()
        }
    );
}

#[test]
fn test_library_call_assert_fails() {
    let mut state = create_test_state();
    let inner_entry_point_selector = selector_from_name("assert_eq");
    let calldata = calldata![
        Felt::from(TEST_CLASS_HASH),  // Class hash.
        inner_entry_point_selector.0, // Function selector.
        Felt::TWO,                    // Calldata length.
        Felt::ZERO,                   // Calldata: first assert value.
        Felt::ONE                     // Calldata: second assert value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_library_call"),
        calldata,
        class_hash: Some(class_hash!(TEST_CLASS_HASH)),
        ..trivial_external_entry_point()
    };

    assert_matches!(
        entry_point_call.execute_directly(&mut state).unwrap_err(),
        EntryPointExecutionError::VirtualMachineExecutionErrorWithTrace { trace, .. } if trace.contains("x != y")
    );
}

#[test]
fn test_nested_library_call() {
    let mut state = create_test_state();

    let (key, value) = (255_u64, 44_u64);
    let outer_entry_point_selector = selector_from_name("test_library_call");
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let main_entry_point_calldata = calldata![
        Felt::from(TEST_CLASS_HASH),  // Class hash.
        outer_entry_point_selector.0, // Library call function selector.
        inner_entry_point_selector.0, // Storage function selector.
        Felt::from(key),              // Calldata: address.
        Felt::from(value)             // Calldata: value.
    ];

    // Create expected call info tree.
    let main_entry_point = CallEntryPoint {
        entry_point_selector: selector_from_name("test_nested_library_call"),
        calldata: main_entry_point_calldata,
        class_hash: Some(class_hash!(TEST_CLASS_HASH)),
        initial_gas: 9999906600,
        ..trivial_external_entry_point()
    };
    let nested_storage_entry_point = CallEntryPoint {
        entry_point_selector: inner_entry_point_selector,
        calldata: calldata![Felt::from(key + 1), Felt::from(value + 1)],
        class_hash: Some(class_hash!(TEST_CLASS_HASH)),
        code_address: None,
        call_type: CallType::Delegate,
        initial_gas: 9999720720,
        ..trivial_external_entry_point()
    };
    let library_entry_point = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata: calldata![
            Felt::from(TEST_CLASS_HASH),  // Class hash.
            inner_entry_point_selector.0, // Storage function selector.
            Felt::TWO,                    // Calldata: address.
            Felt::from(key + 1),          // Calldata: address.
            Felt::from(value + 1)         // Calldata: value.
        ],
        class_hash: Some(class_hash!(TEST_CLASS_HASH)),
        code_address: None,
        call_type: CallType::Delegate,
        initial_gas: 9999814150,
        ..trivial_external_entry_point()
    };
    let storage_entry_point = CallEntryPoint {
        calldata: calldata![Felt::from(key), Felt::from(value)],
        initial_gas: 9999625070,
        ..nested_storage_entry_point
    };
    let storage_entry_point_vm_resources = VmExecutionResources {
        n_steps: 143,
        n_memory_holes: 1,
        builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 5)]),
    };
    let nested_storage_call_info = CallInfo {
        call: nested_storage_entry_point,
        execution: CallExecution {
            retdata: retdata![Felt::from(value + 1)],
            gas_consumed: REQUIRED_GAS_STORAGE_READ_WRITE_TEST,
            ..CallExecution::default()
        },
        vm_resources: storage_entry_point_vm_resources.clone(),
        storage_read_values: vec![Felt::from(value + 1)],
        accessed_storage_keys: HashSet::from([StorageKey(patricia_key!(key + 1))]),
        ..Default::default()
    };
    let library_call_vm_resources = VmExecutionResources {
        n_steps: 411,
        n_memory_holes: 2,
        builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 13)]),
    };
    let library_call_info = CallInfo {
        call: library_entry_point,
        execution: CallExecution {
            retdata: retdata![Felt::from(value + 1)],
            gas_consumed: REQUIRED_GAS_LIBRARY_CALL_TEST,
            ..CallExecution::default()
        },
        vm_resources: library_call_vm_resources,
        inner_calls: vec![nested_storage_call_info],
        ..Default::default()
    };
    let storage_call_info = CallInfo {
        call: storage_entry_point,
        execution: CallExecution {
            retdata: retdata![Felt::from(value)],
            gas_consumed: REQUIRED_GAS_STORAGE_READ_WRITE_TEST,
            ..CallExecution::default()
        },
        vm_resources: storage_entry_point_vm_resources,
        storage_read_values: vec![Felt::from(value)],
        accessed_storage_keys: HashSet::from([StorageKey(patricia_key!(key))]),
        ..Default::default()
    };

    let main_call_vm_resources = VmExecutionResources {
        n_steps: 765,
        n_memory_holes: 4,
        builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 23)]),
    };
    let expected_call_info = CallInfo {
        call: main_entry_point.clone(),
        execution: CallExecution {
            retdata: retdata![Felt::from(value)],
            gas_consumed: 316180,
            ..CallExecution::default()
        },
        vm_resources: main_call_vm_resources,
        inner_calls: vec![library_call_info, storage_call_info],
        ..Default::default()
    };

    assert_eq!(main_entry_point.execute_directly(&mut state).unwrap(), expected_call_info);
}

#[test]
fn test_replace_class() {
    let mut state = create_deploy_test_state();

    // Negative flow.

    // Replace with undeclared class hash.
    let entry_point_call = CallEntryPoint {
        calldata: calldata![Felt::from(1234_u16)],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point()
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert!(error.contains("is not declared"));

    // Replace with Cairo 0 class hash.
    let v0_class_hash = class_hash!(5678_u16);
    let v0_contract_class = ContractClassV0::from_file(TEST_EMPTY_CONTRACT_CAIRO0_PATH).into();
    state.set_contract_class(v0_class_hash, v0_contract_class).unwrap();

    let entry_point_call = CallEntryPoint {
        calldata: calldata![v0_class_hash.0],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point()
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert!(error.contains("Cannot replace V1 class hash with V0 class hash"));

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
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed: 14450, ..Default::default() }
    );
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), new_class_hash);
}

#[test]
fn test_secp256k1() {
    let mut state = create_test_state();

    let calldata = Calldata(vec![].into());
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_secp256k1"),
        calldata,
        ..trivial_external_entry_point()
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed: 17210900_u64, ..Default::default() }
    );
}

#[test]
fn test_secp256r1() {
    let mut state = create_test_state();

    let calldata = Calldata(vec![].into());
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_secp256r1"),
        calldata,
        ..trivial_external_entry_point()
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed: 27650390_u64, ..Default::default() }
    );
}

#[test]
fn test_send_message_to_l1() {
    let mut state = create_test_state();

    let to_address = Felt::from(1234_u16);
    let payload = vec![Felt::from(2019_u16), Felt::from(2020_u16), Felt::from(2021_u16)];
    let calldata = Calldata(
        concat(vec![
            vec![
                to_address,
                // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the
                // convertion works.
                Felt::from(u64::try_from(payload.len()).expect("Failed to convert usize to u64.")),
            ],
            payload.clone(),
        ])
        .into(),
    );
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_send_message_to_l1"),
        calldata,
        ..trivial_external_entry_point()
    };

    let to_address = EthAddress::try_from(to_address).unwrap();
    let message = MessageToL1 { to_address, payload: L2ToL1Payload(payload) };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            l2_to_l1_messages: vec![OrderedL2ToL1Message { order: 0, message }],
            gas_consumed: 37990,
            ..Default::default()
        }
    );
}

#[test_case(
    class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
    calldata![
    Felt::from(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
    ContractAddressSalt::default().0,            // Contract_address_salt.
    Felt::ZERO,                           // Calldata length.
    Felt::ZERO                            // deploy_from_zero.
    ],
    calldata![],
    None ;
    "No constructor: Positive flow")]
#[test_case(
    class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
    calldata![
        Felt::from(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0,            // Contract_address_salt.
        Felt::TWO,                           // Calldata length.
        Felt::TWO,                           // Calldata: address.
        Felt::ONE,                           // Calldata: value.
        Felt::ZERO                            // deploy_from_zero.
    ],
    calldata![
        Felt::TWO,                           // Calldata: arg1.
        Felt::ONE                            // Calldata: arg2.
    ],
    Some(
    "Invalid input: constructor_calldata; Cannot pass calldata to a contract with no constructor.");
    "No constructor: Negative flow: nonempty calldata")]
#[test_case(
    class_hash!(TEST_CLASS_HASH),
    calldata![
        Felt::from(TEST_CLASS_HASH),     // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        Felt::TWO,                // Calldata length.
        Felt::ONE,                // Calldata: arg1.
        Felt::ONE,                // Calldata: arg2.
        Felt::ZERO                 // deploy_from_zero.
    ],
    calldata![
        Felt::ONE,                // Calldata: arg1.
        Felt::ONE                 // Calldata: arg2.
    ],
    None;
    "With constructor: Positive flow")]
#[test_case(
    class_hash!(TEST_CLASS_HASH),
    calldata![
        Felt::from(TEST_CLASS_HASH),     // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        Felt::TWO,                // Calldata length.
        Felt::THREE,                // Calldata: arg1.
        Felt::THREE,                // Calldata: arg2.
        Felt::ZERO                 // deploy_from_zero.
    ],
    calldata![
        Felt::THREE,                // Calldata: arg1.
        Felt::THREE                 // Calldata: arg2.
    ],
    Some("is unavailable for deployment.");
    "With constructor: Negative flow: deploy to the same address")]
fn test_deploy(
    class_hash: ClassHash,
    calldata: Calldata,
    constructor_calldata: Calldata,
    expected_error: Option<&str>,
) {
    let mut state = create_deploy_test_state();
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
    let deploy_call = &entry_point_call.execute_directly(&mut state).unwrap().inner_calls[0];
    assert_eq!(deploy_call.call.storage_address, contract_address);
    let mut retdata = retdata![];
    let gas_consumed = if constructor_calldata.0.is_empty() {
        0
    } else {
        retdata.0.push(constructor_calldata.0[0]);
        16640
    };
    assert_eq!(
        deploy_call.execution,
        CallExecution { retdata, gas_consumed, ..CallExecution::default() }
    );
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), class_hash);
}

#[test]
fn test_out_of_gas() {
    let mut state = create_test_state();

    let key = Felt::from(1234_u16);
    let value = Felt::from(18_u8);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        initial_gas: REQUIRED_GAS_STORAGE_READ_WRITE_TEST - 1,
        ..trivial_external_entry_point()
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err();
    assert_matches!(error, EntryPointExecutionError::ExecutionFailed{ error_data }
        if error_data == vec![Felt::from_raw_const(OUT_OF_GAS_ERROR)]);
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
