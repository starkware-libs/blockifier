use std::collections::HashSet;

use rstest::rstest;
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::{patricia_key, stark_felt};

use crate::execution::call_info::{CallExecution, CallInfo, ExecutionSummary, OrderedEvent};
use crate::execution::entry_point::CallEntryPoint;
use crate::transaction::objects::TransactionExecutionInfo;

#[rstest]
#[case(0, 0)]
#[case(0, 2)]
#[case(1, 3)]
#[case(2, 0)]
// TODO(Ayelet, 20/02/2024): Add test with nested inner calls.
fn test_transaction_execution_info_with_different_event_scenarios(
    #[case] num_of_execute_events: usize,
    #[case] num_of_inner_calls: usize,
) {
    fn call_info_with_x_events(num_of_events: usize, num_of_inner_calls: usize) -> CallInfo {
        CallInfo {
            execution: CallExecution {
                events: (0..num_of_events).map(|_i| OrderedEvent::default()).collect(),
                ..Default::default()
            },
            inner_calls: (0..num_of_inner_calls).map(|_i| call_info_with_x_events(1, 0)).collect(),
            ..Default::default()
        }
    }

    let num_of_validate_events = 2;
    let num_of_fee_transfer_events = 1;

    let transaction_execution_info = TransactionExecutionInfo {
        validate_call_info: Some(call_info_with_x_events(num_of_validate_events, 0)),
        execute_call_info: Some(call_info_with_x_events(num_of_execute_events, num_of_inner_calls)),
        fee_transfer_call_info: Some(call_info_with_x_events(num_of_fee_transfer_events, 0)),
        ..Default::default()
    };

    assert_eq!(
        transaction_execution_info.get_number_of_events(),
        num_of_validate_events
            + num_of_execute_events
            + num_of_fee_transfer_events
            + num_of_inner_calls
    );
}

fn create_classhash_hashset(
    class_hash1: ClassHash,
    class_hash2: ClassHash,
    class_hash3: ClassHash,
) -> HashSet<ClassHash> {
    let mut hash_set = HashSet::new();
    hash_set.insert(class_hash1);
    hash_set.insert(class_hash2);
    hash_set.insert(class_hash3);
    hash_set
}

fn create_storage_key_hashset(
    storage_key1: StorageKey,
    storage_key2: Option<StorageKey>,
    storage_key3: Option<StorageKey>,
) -> HashSet<StorageKey> {
    let mut hash_set = HashSet::new();
    hash_set.insert(storage_key1);
    if let Some(storage_key) = storage_key2 {
        hash_set.insert(storage_key);
    }
    if let Some(storage_key) = storage_key3 {
        hash_set.insert(storage_key);
    }
    hash_set
}

fn create_contract_address_storage_key_hashset(
    storage_key1: (ContractAddress, StorageKey),
    storage_key2: Option<(ContractAddress, StorageKey)>,
    storage_key3: Option<(ContractAddress, StorageKey)>,
) -> HashSet<(ContractAddress, StorageKey)> {
    let mut hash_set = HashSet::new();
    hash_set.insert(storage_key1);
    if let Some(storage_key) = storage_key2 {
        hash_set.insert(storage_key);
    }
    if let Some(storage_key) = storage_key3 {
        hash_set.insert(storage_key);
    }
    hash_set
}

#[derive(Debug, Default)]
struct CallInfoParameters {
    num_of_events: usize,
    class_hash: ClassHash,
    storage_address: ContractAddress,
    storage_key: StorageKey,
}

impl CallInfoParameters {
    fn new(
        num_of_events: usize,
        class_hash: ClassHash,
        storage_address: &str,
        storage_key: &str,
    ) -> Self {
        CallInfoParameters {
            num_of_events,
            class_hash,
            storage_address: ContractAddress(patricia_key!(storage_address)),
            storage_key: StorageKey(patricia_key!(storage_key)),
        }
    }
}

fn create_call_info(params: &CallInfoParameters) -> CallInfo {
    CallInfo {
        call: CallEntryPoint {
            class_hash: Some(params.class_hash),
            storage_address: params.storage_address,
            ..Default::default()
        },
        execution: CallExecution {
            events: (0..params.num_of_events).map(|_| OrderedEvent::default()).collect(),
            ..Default::default()
        },
        accessed_storage_keys: create_storage_key_hashset(params.storage_key, None, None),
        ..Default::default()
    }
}

#[rstest]
#[case(
    CallInfoParameters::new(1, ClassHash(stark_felt!("0x1")), "0x1", "0x1"),
    CallInfoParameters::new(2, ClassHash(stark_felt!("0x2")), "0x2", "0x2"),
    CallInfoParameters::new(3, ClassHash(stark_felt!("0x3")), "0x3", "0x3")
)]
fn test_summarize(
    #[case] validate_params: CallInfoParameters,
    #[case] execute_params: CallInfoParameters,
    #[case] fee_transfer_params: CallInfoParameters,
) {
    let validate_call_info = create_call_info(&validate_params);
    let execute_call_info = create_call_info(&execute_params);
    let fee_transfer_call_info = create_call_info(&fee_transfer_params);

    let transaction_execution_info = TransactionExecutionInfo {
        validate_call_info: Some(validate_call_info),
        execute_call_info: Some(execute_call_info),
        fee_transfer_call_info: Some(fee_transfer_call_info),
        ..Default::default()
    };

    let expected_summary = ExecutionSummary {
        executed_class_hashes: create_classhash_hashset(
            validate_params.class_hash,
            execute_params.class_hash,
            fee_transfer_params.class_hash,
        ),
        visited_storage_entries: create_contract_address_storage_key_hashset(
            (validate_params.storage_address, validate_params.storage_key),
            Some((execute_params.storage_address, execute_params.storage_key)),
            Some((fee_transfer_params.storage_address, fee_transfer_params.storage_key)),
        ),
        n_events: validate_params.num_of_events
            + execute_params.num_of_events
            + fee_transfer_params.num_of_events,
    };

    // Call the summarize method
    let actual_summary = transaction_execution_info.summarize();

    // Compare the actual result with the expected result
    assert_eq!(actual_summary.executed_class_hashes, expected_summary.executed_class_hashes);
    assert_eq!(actual_summary.visited_storage_entries, expected_summary.visited_storage_entries);
    assert_eq!(actual_summary.n_events, expected_summary.n_events);
}
