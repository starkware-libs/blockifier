use std::collections::HashMap;

use assert_matches::assert_matches;
use pretty_assertions::assert_eq;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector, Nonce, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::state::{EntryPointType, StorageKey};
use starknet_api::transaction::{
    Calldata, EventContent, EventData, EventKey, Fee, InvokeTransaction, TransactionHash,
    TransactionSignature, TransactionVersion,
};
use starknet_api::{patky, shash};

use crate::abi::abi_utils::get_selector_from_name;
use crate::execution::entry_point::{CallEntryPoint, CallExecution, CallInfo, Retdata};
use crate::retdata;
use crate::state::cached_state::{CachedState, DictStateReader};
use crate::state::state_api::State;
use crate::test_utils::{
    get_contract_class, ACCOUNT_CONTRACT_PATH, ERC20_CONTRACT_PATH, RETURN_RESULT_SELECTOR,
    TEST_ACCOUNT_CONTRACT_ADDRESS, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH,
    TEST_CONTRACT_ADDRESS, TEST_CONTRACT_PATH, TEST_ERC20_ACCOUNT_BALANCE_KEY,
    TEST_ERC20_CONTRACT_ADDRESS, TEST_ERC20_CONTRACT_CLASS_HASH, TEST_ERC20_SEQUENCER_BALANCE_KEY,
    TEST_SEQUENCER_CONTRACT_ADDRESS,
};
use crate::transaction::constants::{
    EXECUTE_ENTRY_POINT_SELECTOR, TRANSFER_ENTRY_POINT_SELECTOR, TRANSFER_EVENT_NAME,
    VALIDATE_ENTRY_POINT_SELECTOR,
};
use crate::transaction::errors::{FeeTransferError, TransactionExecutionError};
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionInfo};
use crate::transaction::ExecuteTransaction;

fn create_test_state() -> CachedState<DictStateReader> {
    let test_contract_class_hash = ClassHash(shash!(TEST_CLASS_HASH));
    let test_account_contract_class_hash = ClassHash(shash!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let test_erc20_class_hash = ClassHash(shash!(TEST_ERC20_CONTRACT_CLASS_HASH));
    let class_hash_to_class = HashMap::from([
        (test_account_contract_class_hash, get_contract_class(ACCOUNT_CONTRACT_PATH)),
        (test_contract_class_hash, get_contract_class(TEST_CONTRACT_PATH)),
        (test_erc20_class_hash, get_contract_class(ERC20_CONTRACT_PATH)),
    ]);
    let test_contract_address = ContractAddress(patky!(TEST_CONTRACT_ADDRESS));
    let test_account_contract_address = ContractAddress(patky!(TEST_ACCOUNT_CONTRACT_ADDRESS));
    let test_erc20_contract_address = ContractAddress(patky!(TEST_ERC20_CONTRACT_ADDRESS));
    let address_to_class_hash = HashMap::from([
        (test_contract_address, test_contract_class_hash),
        (test_account_contract_address, test_account_contract_class_hash),
        (test_erc20_contract_address, test_erc20_class_hash),
    ]);
    let test_erc20_account_balance_key = StorageKey(patky!(TEST_ERC20_ACCOUNT_BALANCE_KEY));
    let test_erc20_sequencer_balance_key = StorageKey(patky!(TEST_ERC20_SEQUENCER_BALANCE_KEY));
    let storage_view = HashMap::from([
        ((test_erc20_contract_address, test_erc20_sequencer_balance_key), shash!(0)),
        (
            (test_erc20_contract_address, test_erc20_account_balance_key),
            shash!(get_tested_actual_fee().0 as u64),
        ),
    ]);
    CachedState::new(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        storage_view,
        ..Default::default()
    })
}

fn get_tested_valid_invoke_tx() -> InvokeTransaction {
    let execute_calldata = Calldata(
        vec![
            shash!(TEST_CONTRACT_ADDRESS),  // Contract address.
            shash!(RETURN_RESULT_SELECTOR), // EP selector.
            shash!(1),                      // Calldata length.
            shash!(2),                      // Calldata: num.
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
        sender_address: ContractAddress(patky!(TEST_ACCOUNT_CONTRACT_ADDRESS)),
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
    let calldata = tx.calldata.clone();

    let actual_execution_info = tx.execute(&mut state).unwrap();

    // Create expected execution info object.
    let account_contract_address = ContractAddress(patky!(TEST_ACCOUNT_CONTRACT_ADDRESS));
    let expected_validate_call_info = CallInfo {
        call: CallEntryPoint {
            class_hash: None,
            entry_point_type: EntryPointType::External,
            entry_point_selector: EntryPointSelector(shash!(VALIDATE_ENTRY_POINT_SELECTOR)),
            calldata,
            storage_address: account_contract_address,
            caller_address: ContractAddress::default(),
        },
        // The account contract we use for testing has a trivial `validate` function.
        execution: CallExecution { retdata: retdata![] },
        ..Default::default()
    };

    let expected_return_result_calldata = Calldata(vec![shash!(2)].into());
    let expected_return_result_call = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(RETURN_RESULT_SELECTOR)),
        class_hash: None,
        entry_point_type: EntryPointType::External,
        calldata: expected_return_result_calldata.clone(),
        storage_address: ContractAddress(patky!(TEST_CONTRACT_ADDRESS)),
        caller_address: account_contract_address,
    };
    let expected_execute_call = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(EXECUTE_ENTRY_POINT_SELECTOR)),
        ..expected_validate_call_info.call.clone()
    };

    let expected_return_result_retdata = Retdata(expected_return_result_calldata.0);
    let expected_execute_call_info = CallInfo {
        call: expected_execute_call,
        execution: CallExecution { retdata: expected_return_result_retdata.clone() },
        inner_calls: vec![CallInfo {
            call: expected_return_result_call,
            execution: CallExecution { retdata: expected_return_result_retdata },
            ..Default::default()
        }],
        ..Default::default()
    };

    let erc20_contract_address = ContractAddress(patky!(TEST_ERC20_CONTRACT_ADDRESS));
    let fee_recipient_address = shash!(TEST_SEQUENCER_CONTRACT_ADDRESS);
    let fee_sender_address = *account_contract_address.0.key();
    let expected_actual_fee = get_tested_actual_fee();
    // The least significant 128 bits of the expected amount transferred.
    let lsb_expected_amount = shash!(expected_actual_fee.0 as u64);
    // The most significant 128 bits of the expected amount transferred.
    let msb_expected_amount = shash!(0);
    let expected_fee_transfer_call = CallEntryPoint {
        class_hash: None,
        entry_point_type: EntryPointType::External,
        entry_point_selector: EntryPointSelector(shash!(TRANSFER_ENTRY_POINT_SELECTOR)),
        calldata: Calldata(
            vec![fee_recipient_address, lsb_expected_amount, msb_expected_amount].into(),
        ),
        storage_address: erc20_contract_address,
        caller_address: account_contract_address,
    };
    let fee_transfer_event = EventContent {
        keys: vec![EventKey(get_selector_from_name(TRANSFER_EVENT_NAME).0)],
        data: EventData(vec![
            fee_sender_address,
            fee_recipient_address,
            lsb_expected_amount,
            msb_expected_amount,
        ]),
    };
    let expected_fee_transfer_call_info = CallInfo {
        call: expected_fee_transfer_call,
        execution: CallExecution { retdata: retdata![shash!(true as u64)] },
        events: vec![fee_transfer_event],
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
    let expected_sequencer_balance = lsb_expected_amount;
    assert_eq!(
        state
            .get_storage_at(
                erc20_contract_address,
                StorageKey(patky!(TEST_ERC20_ACCOUNT_BALANCE_KEY))
            )
            .unwrap(),
        &shash!(expected_account_balance)
    );
    assert_eq!(
        state
            .get_storage_at(
                erc20_contract_address,
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
