use std::collections::HashMap;

use assert_matches::assert_matches;
use pretty_assertions::assert_eq;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector, Nonce, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::state::{EntryPointType, StorageKey};
use starknet_api::transaction::{
    CallData, Fee, InvokeTransaction, TransactionHash, TransactionSignature, TransactionVersion,
};
use starknet_api::{patky, shash};

use crate::execution::entry_point::{CallEntryPoint, CallExecution, CallInfo};
use crate::state::cached_state::{CachedState, DictStateReader};
use crate::test_utils::{
    get_contract_class, ACCOUNT_CONTRACT_PATH, ERC20_CONTRACT_PATH, RETURN_RESULT_SELECTOR,
    TEST_ACCOUNT_CONTRACT_ADDRESS, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CONTRACT_ADDRESS,
    TEST_ERC20_ACCOUNT_BALANCE_KEY, TEST_ERC20_CONTRACT_ADDRESS, TEST_ERC20_CONTRACT_CLASS_HASH,
    TEST_ERC20_SEQUENCER_BALANCE_KEY, TEST_SEQUENCER_ADDRESS,
};
use crate::transaction::constants::{
    CALL_CONTRACT_CALLDATA_INDEX, EXECUTE_ENTRY_POINT_SELECTOR, TRANSFER_ENTRY_POINT_SELECTOR,
    VALIDATE_ENTRY_POINT_SELECTOR,
};
use crate::transaction::errors::{FeeTransferError, TransactionExecutionError};
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionInfo};
use crate::transaction::ExecuteTransaction;

fn create_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = HashMap::from([
        (
            ClassHash(shash!(TEST_ACCOUNT_CONTRACT_CLASS_HASH)),
            get_contract_class(ACCOUNT_CONTRACT_PATH),
        ),
        (
            ClassHash(shash!(TEST_ERC20_CONTRACT_CLASS_HASH)),
            get_contract_class(ERC20_CONTRACT_PATH),
        ),
    ]);
    let storage_view = HashMap::from([
        (
            (
                ContractAddress(patky!(TEST_ERC20_CONTRACT_ADDRESS)),
                StorageKey(patky!(TEST_ERC20_ACCOUNT_BALANCE_KEY)),
            ),
            shash!(get_tested_actual_fee().0 as u64),
        ),
        (
            (
                ContractAddress(patky!(TEST_ERC20_CONTRACT_ADDRESS)),
                StorageKey(patky!(TEST_ERC20_SEQUENCER_BALANCE_KEY)),
            ),
            shash!(0),
        ),
    ]);
    CachedState::new(DictStateReader { class_hash_to_class, storage_view, ..Default::default() })
}

fn get_tested_valid_invoke_tx() -> InvokeTransaction {
    let execute_calldata = CallData(
        vec![
            shash!(TEST_CONTRACT_ADDRESS),  // Contract address.
            shash!(RETURN_RESULT_SELECTOR), // EP selector.
            shash!(1),                      // Calldata length.
            shash!(0),                      // Calldata.
        ]
        .into(),
    );

    InvokeTransaction {
        transaction_hash: TransactionHash(StarkHash::default()),
        max_fee: Fee(1),
        version: TransactionVersion(shash!(1)),
        signature: TransactionSignature(vec![StarkHash::default()]),
        nonce: Nonce::default(),
        // TODO(Adi, 25/12/2022): Use an actual contract_address once there is a mapping from a
        // contract address to its class hash.
        sender_address: ContractAddress::try_from(shash!(TEST_ACCOUNT_CONTRACT_ADDRESS)).unwrap(),
        entry_point_selector: None,
        calldata: execute_calldata,
    }
}

fn get_tested_actual_fee() -> Fee {
    Fee(1)
}

#[test]
fn test_invoke_tx() {
    let mut state = create_test_state();
    let tx = get_tested_valid_invoke_tx();

    let actual_execution_info = tx.execute(&mut state).unwrap();

    // Create expected execution info object.
    let expected_validate_call_info = CallInfo {
        call: CallEntryPoint {
            class_hash: ClassHash(shash!(TEST_ACCOUNT_CONTRACT_CLASS_HASH)),
            entry_point_type: EntryPointType::External,
            entry_point_selector: EntryPointSelector(shash!(VALIDATE_ENTRY_POINT_SELECTOR)),
            calldata: tx.calldata.clone(),
            storage_address: ContractAddress::try_from(shash!(TEST_ACCOUNT_CONTRACT_ADDRESS))
                .unwrap(),
        },
        // 'account_without_some_syscalls' has a trivial `validate` function.
        execution: CallExecution { retdata: vec![] },
        ..Default::default()
    };

    let expected_execute_call = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(EXECUTE_ENTRY_POINT_SELECTOR)),
        ..expected_validate_call_info.call.clone()
    };

    let expected_execute_call_info = CallInfo {
        call: expected_execute_call,
        // The called EP simply returns the calldata it was given.
        execution: CallExecution {
            retdata: tx.calldata.0[CALL_CONTRACT_CALLDATA_INDEX..].to_vec(),
        },
        ..Default::default()
    };

    let expected_actual_fee = get_tested_actual_fee();
    let expected_fee_transfer_call = CallEntryPoint {
        class_hash: ClassHash(shash!(TEST_ERC20_CONTRACT_CLASS_HASH)),
        entry_point_type: EntryPointType::External,
        entry_point_selector: EntryPointSelector(shash!(TRANSFER_ENTRY_POINT_SELECTOR)),
        calldata: CallData(
            vec![
                // TODO(Adi, 15/01/2023): The sender argument should be removed once
                // `get_caller_address` is implemented.
                shash!(TEST_SEQUENCER_ADDRESS),        // Recipient.
                shash!(TEST_ACCOUNT_CONTRACT_ADDRESS), // Sender.
                shash!(expected_actual_fee.0 as u64),  // Amount (lower 128-bit).
                shash!(0),                             // Amount (upper 128-bit).
            ]
            .into(),
        ),
        storage_address: ContractAddress::try_from(shash!(TEST_ERC20_CONTRACT_ADDRESS)).unwrap(),
    };
    let expected_fee_transfer_call_info = CallInfo {
        call: expected_fee_transfer_call,
        execution: CallExecution { retdata: vec![shash!(true as u64)] },
        ..Default::default()
    };

    let expected_execution_info = TransactionExecutionInfo {
        validate_call_info: expected_validate_call_info,
        execute_call_info: Some(expected_execute_call_info),
        fee_transfer_call_info: expected_fee_transfer_call_info,
        actual_fee: expected_actual_fee,
        actual_resources: ResourcesMapping::default(),
    };

    // Test execution info result.
    assert_eq!(actual_execution_info, expected_execution_info);

    // Test final balances.
    let expected_account_balance = shash!(0);
    let expected_sequencer_balance = shash!(expected_actual_fee.0 as u64);
    assert_eq!(
        state
            .get_storage_at(
                ContractAddress(patky!(TEST_ERC20_CONTRACT_ADDRESS)),
                StorageKey(patky!(TEST_ERC20_ACCOUNT_BALANCE_KEY))
            )
            .unwrap(),
        &shash!(expected_account_balance)
    );
    assert_eq!(
        state
            .get_storage_at(
                ContractAddress(patky!(TEST_ERC20_CONTRACT_ADDRESS)),
                StorageKey(patky!(TEST_ERC20_SEQUENCER_BALANCE_KEY))
            )
            .unwrap(),
        &shash!(expected_sequencer_balance)
    );
}

#[test]
fn test_negative_invoke_tx_flows() {
    let mut state = create_test_state();
    let valid_tx = get_tested_valid_invoke_tx();

    // Invalid version.
    // Note: there is no need to test for a negative version, as it cannot be constructed.
    let invalid_tx_version = TransactionVersion(shash!(0));
    let invalid_tx = InvokeTransaction { version: invalid_tx_version, ..valid_tx.clone() };
    let execution_error = invalid_tx.execute(&mut state).unwrap_err();

    // Test error.
    let expected_allowed_versions = vec![TransactionVersion(shash!(1))];
    assert_matches!(
        execution_error,
        TransactionExecutionError::InvalidTransactionVersion {
            tx_version,
            allowed_versions,
        }
        if (tx_version, &allowed_versions) == (invalid_tx_version, &expected_allowed_versions)
    );

    // Insufficient fee.
    let tx_max_fee = Fee(0);
    let invalid_tx = InvokeTransaction { max_fee: tx_max_fee, ..valid_tx };
    let execution_error = invalid_tx.execute(&mut state).unwrap_err();

    // Test error.
    let expected_actual_fee = get_tested_actual_fee();
    assert_matches!(
        execution_error,
        TransactionExecutionError::FeeTransferError(FeeTransferError::MaxFeeExceeded {
            max_fee,
            actual_fee,
        })
        if (max_fee, actual_fee) == (tx_max_fee, expected_actual_fee)
    );
}
