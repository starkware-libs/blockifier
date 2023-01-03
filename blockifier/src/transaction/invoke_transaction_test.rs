use std::collections::HashMap;

use assert_matches::assert_matches;
use pretty_assertions::assert_eq;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::{EntryPointType, StorageKey};
use starknet_api::transaction::{
    Calldata, EventContent, EventData, EventKey, Fee, InvokeTransaction, TransactionHash,
    TransactionSignature, TransactionVersion,
};
use starknet_api::{calldata, patricia_key, stark_felt};

use crate::abi::abi_utils::get_selector_from_name;
use crate::block_context::BlockContext;
use crate::execution::entry_point::{CallEntryPoint, CallExecution, CallInfo, Retdata};
use crate::retdata;
use crate::state::cached_state::{CachedState, DictStateReader};
use crate::state::state_api::State;
use crate::test_utils::{
    get_contract_class, ACCOUNT_CONTRACT_PATH, ERC20_CONTRACT_PATH, RETURN_RESULT_SELECTOR,
    TEST_ACCOUNT_CONTRACT_ADDRESS, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH,
    TEST_CONTRACT_ADDRESS, TEST_CONTRACT_PATH, TEST_ERC20_ACCOUNT_BALANCE_KEY,
    TEST_ERC20_CONTRACT_CLASS_HASH, TEST_ERC20_SEQUENCER_BALANCE_KEY,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants::{
    EXECUTE_ENTRY_POINT_NAME, TRANSFER_ENTRY_POINT_NAME, TRANSFER_EVENT_NAME,
    VALIDATE_ENTRY_POINT_NAME,
};
use crate::transaction::errors::{FeeTransferError, TransactionExecutionError};
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionInfo};

fn create_test_state() -> CachedState<DictStateReader> {
    let block_context = BlockContext::get_test_block_context();

    let test_contract_class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    let test_account_class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let test_erc20_class_hash = ClassHash(stark_felt!(TEST_ERC20_CONTRACT_CLASS_HASH));
    let class_hash_to_class = HashMap::from([
        (test_account_class_hash, get_contract_class(ACCOUNT_CONTRACT_PATH)),
        (test_contract_class_hash, get_contract_class(TEST_CONTRACT_PATH)),
        (test_erc20_class_hash, get_contract_class(ERC20_CONTRACT_PATH)),
    ]);
    let test_contract_address = ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS));
    let test_account_address = ContractAddress(patricia_key!(TEST_ACCOUNT_CONTRACT_ADDRESS));
    let test_erc20_address = block_context.fee_token_address;
    let address_to_class_hash = HashMap::from([
        (test_contract_address, test_contract_class_hash),
        (test_account_address, test_account_class_hash),
        (test_erc20_address, test_erc20_class_hash),
    ]);
    let test_erc20_account_balance_key = StorageKey(patricia_key!(TEST_ERC20_ACCOUNT_BALANCE_KEY));
    let test_erc20_sequencer_balance_key =
        StorageKey(patricia_key!(TEST_ERC20_SEQUENCER_BALANCE_KEY));
    let storage_view = HashMap::from([
        ((test_erc20_address, test_erc20_sequencer_balance_key), stark_felt!(0)),
        (
            (test_erc20_address, test_erc20_account_balance_key),
            stark_felt!(get_tested_actual_fee().0 as u64),
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
    let execute_calldata = calldata![
        stark_felt!(TEST_CONTRACT_ADDRESS),  // Contract address.
        stark_felt!(RETURN_RESULT_SELECTOR), // EP selector.
        stark_felt!(1),                      // Calldata length.
        stark_felt!(2)                       // Calldata: num.
    ];

    InvokeTransaction {
        transaction_hash: TransactionHash(StarkHash::default()),
        max_fee: Fee(1),
        version: TransactionVersion(stark_felt!(1)),
        signature: TransactionSignature(vec![StarkHash::default()]),
        nonce: Nonce::default(),
        sender_address: ContractAddress(patricia_key!(TEST_ACCOUNT_CONTRACT_ADDRESS)),
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
    let block_context = BlockContext::get_test_block_context();

    // Extract invoke transaction fields for testing, as the transaction execution consumes
    // the transaction.
    let invoke_tx = get_tested_valid_invoke_tx();
    let calldata = invoke_tx.calldata.clone();
    let sender_address = invoke_tx.sender_address;

    let account_tx = AccountTransaction::Invoke(invoke_tx);
    let actual_execution_info = account_tx.execute(&mut state, &block_context).unwrap();

    // Build expected validate call info.
    let expected_account_address = ContractAddress(patricia_key!(TEST_ACCOUNT_CONTRACT_ADDRESS));
    let expected_validate_call_info = CallInfo {
        call: CallEntryPoint {
            class_hash: None,
            entry_point_type: EntryPointType::External,
            entry_point_selector: get_selector_from_name(VALIDATE_ENTRY_POINT_NAME),
            calldata,
            storage_address: expected_account_address,
            caller_address: ContractAddress::default(),
        },
        // The account contract we use for testing has a trivial `validate` function.
        execution: CallExecution { retdata: retdata![] },
        ..Default::default()
    };

    // Build expected execute call info.
    let expected_return_result_calldata = vec![stark_felt!(2)];
    let expected_return_result_call = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(RETURN_RESULT_SELECTOR)),
        class_hash: None,
        entry_point_type: EntryPointType::External,
        calldata: Calldata(expected_return_result_calldata.clone().into()),
        storage_address: ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS)),
        caller_address: expected_account_address,
    };
    let expected_execute_call = CallEntryPoint {
        entry_point_selector: get_selector_from_name(EXECUTE_ENTRY_POINT_NAME),
        ..expected_validate_call_info.call.clone()
    };
    let expected_return_result_retdata = Retdata(expected_return_result_calldata.into());
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

    // Build expected fee transfer call info.
    let expected_sequencer_address = *block_context.sequencer_address.0.key();
    let expected_actual_fee = get_tested_actual_fee();
    // The least significant 128 bits of the expected amount transferred.
    let lsb_expected_amount = stark_felt!(expected_actual_fee.0 as u64);
    // The most significant 128 bits of the expected amount transferred.
    let msb_expected_amount = stark_felt!(0);
    let expected_fee_transfer_call = CallEntryPoint {
        class_hash: None,
        entry_point_type: EntryPointType::External,
        entry_point_selector: get_selector_from_name(TRANSFER_ENTRY_POINT_NAME),
        calldata: calldata![
            expected_sequencer_address, // Recipient.
            lsb_expected_amount,
            msb_expected_amount
        ],
        storage_address: block_context.fee_token_address,
        caller_address: expected_account_address,
    };
    let expected_fee_sender_address = *expected_account_address.0.key();
    let expected_fee_transfer_event = EventContent {
        keys: vec![EventKey(get_selector_from_name(TRANSFER_EVENT_NAME).0)],
        data: EventData(vec![
            expected_fee_sender_address,
            expected_sequencer_address, // Recipient.
            lsb_expected_amount,
            msb_expected_amount,
        ]),
    };
    let expected_fee_transfer_call_info = CallInfo {
        call: expected_fee_transfer_call,
        execution: CallExecution { retdata: retdata![stark_felt!(true as u64)] },
        events: vec![expected_fee_transfer_event],
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

    // Test nonce update.
    assert_eq!(*state.get_nonce_at(sender_address).unwrap(), Nonce(stark_felt!(1)));

    // Test final balances.
    let expected_account_balance = stark_felt!(0);
    let expected_sequencer_balance = lsb_expected_amount;
    assert_eq!(
        state
            .get_storage_at(
                block_context.fee_token_address,
                StorageKey(patricia_key!(TEST_ERC20_ACCOUNT_BALANCE_KEY))
            )
            .unwrap(),
        &stark_felt!(expected_account_balance)
    );
    assert_eq!(
        state
            .get_storage_at(
                block_context.fee_token_address,
                StorageKey(patricia_key!(TEST_ERC20_SEQUENCER_BALANCE_KEY))
            )
            .unwrap(),
        &stark_felt!(expected_sequencer_balance)
    );
}

#[test]
fn test_negative_invoke_tx_flows() {
    let mut state = create_test_state();
    let block_context = BlockContext::get_test_block_context();
    let valid_invoke_tx = get_tested_valid_invoke_tx();

    // Invalid version.
    // Note: there is no need to test for a negative version, as it cannot be constructed.
    let invalid_tx_version = TransactionVersion(stark_felt!(0));
    let invalid_tx = AccountTransaction::Invoke(InvokeTransaction {
        version: invalid_tx_version,
        ..valid_invoke_tx.clone()
    });
    let execution_error = invalid_tx.execute(&mut state, &block_context).unwrap_err();

    // Test error.
    let expected_allowed_versions = vec![TransactionVersion(stark_felt!(1))];
    assert_matches!(
        execution_error,
        TransactionExecutionError::InvalidVersion { version, allowed_versions }
        if (version, &allowed_versions) == (invalid_tx_version, &expected_allowed_versions)
    );

    // Insufficient fee.
    let tx_max_fee = Fee(0);
    let invalid_tx = AccountTransaction::Invoke(InvokeTransaction {
        max_fee: tx_max_fee,
        ..valid_invoke_tx.clone()
    });
    let execution_error = invalid_tx.execute(&mut state, &block_context).unwrap_err();

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

    // Invalid nonce.
    // Use a fresh state to facilitate testing.
    let nonce = Nonce(stark_felt!(1));
    let invalid_tx = AccountTransaction::Invoke(InvokeTransaction { nonce, ..valid_invoke_tx });
    let execution_error = invalid_tx.execute(&mut create_test_state(), &block_context).unwrap_err();

    // Test error.
    assert_matches!(
        execution_error,
        TransactionExecutionError::InvalidNonce { expected_nonce, actual_nonce }
        if (expected_nonce, actual_nonce) == (Nonce::default(), nonce)
    );
}
