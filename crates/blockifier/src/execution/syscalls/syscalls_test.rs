use std::collections::{HashMap, HashSet};

use assert_matches::assert_matches;
use cairo_felt::Felt252;
use cairo_vm::vm::runners::builtin_runner::RANGE_CHECK_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use itertools::concat;
use num_traits::Pow;
use pretty_assertions::assert_eq;
use starknet_api::core::{
    calculate_contract_address, ChainId, ClassHash, ContractAddress, EthAddress, Nonce, PatriciaKey,
};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, EventContent, EventData, EventKey, Fee, L2ToL1Payload,
    TransactionHash, TransactionVersion,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants;
use crate::execution::call_info::{
    CallExecution, CallInfo, MessageToL1, OrderedEvent, OrderedL2ToL1Message, Retdata,
};
use crate::execution::common_hints::ExecutionMode;
use crate::execution::contract_class::ContractClassV0;
use crate::execution::entry_point::{CallEntryPoint, CallType};
use crate::execution::errors::EntryPointExecutionError;
use crate::execution::execution_utils::felt_to_stark_felt;
use crate::execution::syscalls::hint_processor::{
    BLOCK_NUMBER_OUT_OF_RANGE_ERROR, OUT_OF_GAS_ERROR,
};
use crate::retdata;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::{
    check_entry_point_execution_error_for_custom_hint, create_calldata, create_deploy_test_state,
    create_test_state, trivial_external_entry_point, CHAIN_ID_NAME, CURRENT_BLOCK_NUMBER,
    CURRENT_BLOCK_TIMESTAMP, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS,
    TEST_EMPTY_CONTRACT_CAIRO0_PATH, TEST_EMPTY_CONTRACT_CLASS_HASH, TEST_SEQUENCER_ADDRESS,
};
use crate::transaction::constants::QUERY_VERSION_BASE_BIT;
use crate::transaction::objects::{
    AccountTransactionContext, CommonAccountFields, DeprecatedAccountTransactionContext,
};

pub const REQUIRED_GAS_STORAGE_READ_WRITE_TEST: u64 = 34650;
pub const REQUIRED_GAS_CALL_CONTRACT_TEST: u64 = 128080;
pub const REQUIRED_GAS_LIBRARY_CALL_TEST: u64 = REQUIRED_GAS_CALL_CONTRACT_TEST;

#[test]
fn test_storage_read_write() {
    let mut state = create_test_state();

    let key = stark_felt!(1234_u16);
    let value = stark_felt!(18_u8);
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
            retdata: retdata![stark_felt!(value)],
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
            stark_felt!(405_u16), // Calldata: address.
            stark_felt!(48_u8),   // Calldata: value.
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
            retdata: retdata![stark_felt!(48_u8)],
            gas_consumed: REQUIRED_GAS_CALL_CONTRACT_TEST,
            ..CallExecution::default()
        }
    );
}

#[test]
fn test_emit_event() {
    let mut state = create_test_state();

    let keys = vec![stark_felt!(2019_u16), stark_felt!(2020_u16)];
    let data = vec![stark_felt!(2021_u16), stark_felt!(2022_u16), stark_felt!(2023_u16)];
    let calldata = Calldata(
        concat(vec![
            vec![stark_felt!(keys.len() as u8)],
            keys.clone(),
            vec![stark_felt!(data.len() as u8)],
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
    let block_number = stark_felt!(upper_bound_block_number);
    let block_hash = stark_felt!(66_u64);
    let key = StorageKey::try_from(block_number).unwrap();
    let block_hash_contract_address =
        ContractAddress::try_from(StarkFelt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS)).unwrap();
    state.set_storage_at(block_hash_contract_address, key, block_hash);

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
    check_entry_point_execution_error_for_custom_hint(
        &error,
        "Unauthorized syscall get_block_hash in execution mode Validate.",
    );

    // Negative flow: Block number out of range.
    let requested_block_number = CURRENT_BLOCK_NUMBER - constants::STORED_BLOCK_HASH_BUFFER + 1;
    let block_number = stark_felt!(requested_block_number);
    let calldata = calldata![block_number];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_get_block_hash"),
        calldata,
        ..trivial_external_entry_point()
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err();
    assert_matches!(error, EntryPointExecutionError::ExecutionFailed{ error_data }
        if error_data == vec![stark_felt!(BLOCK_NUMBER_OUT_OF_RANGE_ERROR)]);
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

#[test_case(
    ExecutionMode::Validate,
    [
        stark_felt!(CURRENT_BLOCK_NUMBER), // Block number.
        stark_felt!(CURRENT_BLOCK_TIMESTAMP), // Block timestamp.
        stark_felt!(0_u16) // Sequencer address.
    ],
    false;
    "Validate execution mode: block info fields should be zeroed.")]
#[test_case(
    ExecutionMode::Execute,
    [
        stark_felt!(CURRENT_BLOCK_NUMBER), // Block number.
        stark_felt!(CURRENT_BLOCK_TIMESTAMP), // Block timestamp.
        stark_felt!(TEST_SEQUENCER_ADDRESS) // Sequencer address.
    ],
    false;
    "Execute execution mode: block info should be as usual.")]
#[test_case(
        ExecutionMode::Execute,
        [
            stark_felt!(CURRENT_BLOCK_NUMBER), // Block number.
            stark_felt!(CURRENT_BLOCK_TIMESTAMP), // Block timestamp.
            stark_felt!(TEST_SEQUENCER_ADDRESS) // Sequencer address.
        ],
        true;
        "Execute execution mode: block info should be as usual. Query.")]
fn test_get_execution_info(
    execution_mode: ExecutionMode,
    expected_block_info: [StarkFelt; 3],
    only_query: bool,
) {
    let mut version = Felt252::from(1_u8);
    if only_query {
        let simulate_version_base = Pow::pow(Felt252::from(2_u8), QUERY_VERSION_BASE_BIT);
        version += simulate_version_base;
    }
    let tx_hash = TransactionHash(stark_felt!(1991_u16));
    let max_fee = Fee(0);
    let nonce = Nonce(stark_felt!(3_u16));
    let sender_address = ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS));
    let expected_tx_info = vec![
        felt_to_stark_felt(&version), // Transaction version.
        *sender_address.0.key(),      // Account address.
        stark_felt!(max_fee.0),       // Max fee.
        tx_hash.0,                    // Transaction hash.
        stark_felt!(&*ChainId(CHAIN_ID_NAME.to_string()).as_hex()), // Chain ID.
        nonce.0,                      // Nonce.
        stark_felt!(0_u16),           // Length of resource bounds array.
    ];
    let entry_point_selector = selector_from_name("test_get_execution_info");
    let expected_call_info = vec![
        stark_felt!(0_u16),                  // Caller address.
        stark_felt!(TEST_CONTRACT_ADDRESS),  // Storage address.
        stark_felt!(entry_point_selector.0), // Entry point selector.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector,
        calldata: Calldata(
            [expected_block_info.to_vec(), expected_tx_info, expected_call_info].concat().into(),
        ),
        ..trivial_external_entry_point()
    };

    let mut state = create_test_state();
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

    let result = match execution_mode {
        ExecutionMode::Validate => entry_point_call
            .execute_directly_given_account_context_in_validate_mode(
                &mut state,
                account_tx_context,
            ),
        ExecutionMode::Execute => {
            entry_point_call.execute_directly_given_account_context(&mut state, account_tx_context)
        }
    };

    assert!(!result.unwrap().execution.failed)
}

#[test]
fn test_library_call() {
    let mut state = create_test_state();

    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let calldata = calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        inner_entry_point_selector.0, // Function selector.
        stark_felt!(2_u8),            // Calldata length.
        stark_felt!(1234_u16),        // Calldata: address.
        stark_felt!(91_u8)            // Calldata: value.
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
            retdata: retdata![stark_felt!(91_u16)],
            gas_consumed: REQUIRED_GAS_LIBRARY_CALL_TEST,
            ..Default::default()
        }
    );
}

#[test]
fn test_nested_library_call() {
    let mut state = create_test_state();

    let (key, value) = (255_u64, 44_u64);
    let outer_entry_point_selector = selector_from_name("test_library_call");
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let main_entry_point_calldata = calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        outer_entry_point_selector.0, // Library call function selector.
        inner_entry_point_selector.0, // Storage function selector.
        stark_felt!(key),             // Calldata: address.
        stark_felt!(value)            // Calldata: value.
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
        calldata: calldata![stark_felt!(key + 1), stark_felt!(value + 1)],
        class_hash: Some(class_hash!(TEST_CLASS_HASH)),
        code_address: None,
        call_type: CallType::Delegate,
        initial_gas: 9999720720,
        ..trivial_external_entry_point()
    };
    let library_entry_point = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata: calldata![
            stark_felt!(TEST_CLASS_HASH), // Class hash.
            inner_entry_point_selector.0, // Storage function selector.
            stark_felt!(2_u8),            // Calldata: address.
            stark_felt!(key + 1),         // Calldata: address.
            stark_felt!(value + 1)        // Calldata: value.
        ],
        class_hash: Some(class_hash!(TEST_CLASS_HASH)),
        code_address: None,
        call_type: CallType::Delegate,
        initial_gas: 9999814150,
        ..trivial_external_entry_point()
    };
    let storage_entry_point = CallEntryPoint {
        calldata: calldata![stark_felt!(key), stark_felt!(value)],
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
            retdata: retdata![stark_felt!(value + 1)],
            gas_consumed: REQUIRED_GAS_STORAGE_READ_WRITE_TEST,
            ..CallExecution::default()
        },
        vm_resources: storage_entry_point_vm_resources.clone(),
        storage_read_values: vec![stark_felt!(value + 1)],
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
            retdata: retdata![stark_felt!(value + 1)],
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
            retdata: retdata![stark_felt!(value)],
            gas_consumed: REQUIRED_GAS_STORAGE_READ_WRITE_TEST,
            ..CallExecution::default()
        },
        vm_resources: storage_entry_point_vm_resources,
        storage_read_values: vec![stark_felt!(value)],
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
            retdata: retdata![stark_felt!(value)],
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
        calldata: calldata![stark_felt!(1234_u16)],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point()
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert!(error.contains("is not declared"));

    // Replace with Cairo 0 class hash.
    let v0_class_hash = class_hash!(5678_u16);
    let v0_contract_class = ContractClassV0::from_file(TEST_EMPTY_CONTRACT_CAIRO0_PATH).into();
    state.set_contract_class(&v0_class_hash, v0_contract_class).unwrap();

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
        CallExecution { gas_consumed: 32602390_u64, ..Default::default() }
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
        CallExecution { gas_consumed: 48708820_u64, ..Default::default() }
    );
}

#[test]
fn test_send_message_to_l1() {
    let mut state = create_test_state();

    let to_address = stark_felt!(1234_u16);
    let payload = vec![stark_felt!(2019_u16), stark_felt!(2020_u16), stark_felt!(2021_u16)];
    let calldata = Calldata(
        concat(vec![vec![to_address, stark_felt!(payload.len() as u64)], payload.clone()]).into(),
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
    stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
    ContractAddressSalt::default().0,            // Contract_address_salt.
    stark_felt!(0_u8),                           // Calldata length.
    stark_felt!(0_u8)                            // deploy_from_zero.
    ],
    calldata![],
    None ;
    "No constructor: Positive flow")]
#[test_case(
    class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
    calldata![
        stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0,            // Contract_address_salt.
        stark_felt!(2_u8),                           // Calldata length.
        stark_felt!(2_u8),                           // Calldata: address.
        stark_felt!(1_u8),                           // Calldata: value.
        stark_felt!(0_u8)                            // deploy_from_zero.
    ],
    calldata![
        stark_felt!(2_u8),                           // Calldata: arg1.
        stark_felt!(1_u8)                            // Calldata: arg2.
    ],
    Some(
    "Invalid input: constructor_calldata; Cannot pass calldata to a contract with no constructor.");
    "No constructor: Negative flow: nonempty calldata")]
#[test_case(
    class_hash!(TEST_CLASS_HASH),
    calldata![
        stark_felt!(TEST_CLASS_HASH),     // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2_u8),                // Calldata length.
        stark_felt!(1_u8),                // Calldata: arg1.
        stark_felt!(1_u8),                // Calldata: arg2.
        stark_felt!(0_u8)                 // deploy_from_zero.
    ],
    calldata![
        stark_felt!(1_u8),                // Calldata: arg1.
        stark_felt!(1_u8)                 // Calldata: arg2.
    ],
    None;
    "With constructor: Positive flow")]
#[test_case(
    class_hash!(TEST_CLASS_HASH),
    calldata![
        stark_felt!(TEST_CLASS_HASH),     // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2_u8),                // Calldata length.
        stark_felt!(3_u8),                // Calldata: arg1.
        stark_felt!(3_u8),                // Calldata: arg2.
        stark_felt!(0_u8)                 // deploy_from_zero.
    ],
    calldata![
        stark_felt!(3_u8),                // Calldata: arg1.
        stark_felt!(3_u8)                 // Calldata: arg2.
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

    let key = stark_felt!(1234_u16);
    let value = stark_felt!(18_u8);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        initial_gas: REQUIRED_GAS_STORAGE_READ_WRITE_TEST - 1,
        ..trivial_external_entry_point()
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err();
    assert_matches!(error, EntryPointExecutionError::ExecutionFailed{ error_data }
        if error_data == vec![stark_felt!(OUT_OF_GAS_ERROR)]);
}

// TODO(yuval): This test should fail once upgrading the dependency on cairo-lang-runner to version
// 2.4.0. To fix it, merge PR https://github.com/starkware-libs/blockifier/pull/1064.
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
    .map(|x| StarkFelt::try_from(x).unwrap())
    .collect();
    let error = EntryPointExecutionError::ExecutionFailed { error_data };
    assert_eq!(
        error.to_string(),
        format!(
            "Execution failed. Failure reason: \"0x{BYTE_ARRAY_MAGIC}, , Execution failure, \
             \\u{{11}}\"."
        )
    );
}

// TODO(yuval): when updating to the compiler of version 2.4.0, use it from
// `cairo_lang_utils::byte_array::BYTE_ARRAY_MAGIC` instead.
const BYTE_ARRAY_MAGIC: &str = "046a6158a16a947e5916b2a2ca68501a45e93d7110e81aa2d6438b1c57c879a3";
