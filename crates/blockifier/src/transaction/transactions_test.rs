use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use assert_matches::assert_matches;
use pretty_assertions::assert_eq;
use starknet_api::core::{
    calculate_contract_address, ClassHash, ContractAddress, Nonce, PatriciaKey,
};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::{EntryPointType, StorageKey};
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransaction, DeployAccountTransaction, EventContent,
    EventData, EventKey, Fee, InvokeTransaction, TransactionVersion,
};
use starknet_api::{calldata, patricia_key, stark_felt};

use crate::abi::abi_utils::get_selector;
use crate::abi::constants::CONSTRUCTOR_ENTRY_POINT_NAME;
use crate::block_context::BlockContext;
use crate::execution::entry_point::{CallEntryPoint, CallExecution, CallInfo, Retdata};
use crate::retdata;
use crate::state::cached_state::{CachedState, DictStateReader};
use crate::state::state_api::State;
use crate::test_utils::{
    get_contract_class, ACCOUNT_CONTRACT_PATH, ERC20_CONTRACT_PATH, TEST_ACCOUNT_CONTRACT_ADDRESS,
    TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS, TEST_CONTRACT_PATH,
    TEST_ERC20_ACCOUNT_BALANCE_KEY, TEST_ERC20_CONTRACT_CLASS_HASH,
    TEST_ERC20_SEQUENCER_BALANCE_KEY,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants::{
    EXECUTE_ENTRY_POINT_NAME, TRANSFER_ENTRY_POINT_NAME, TRANSFER_EVENT_NAME,
    VALIDATE_ENTRY_POINT_NAME,
};
use crate::transaction::errors::{FeeTransferError, TransactionExecutionError};
use crate::transaction::execute_transaction::ExecuteTransaction;
use crate::transaction::objects::{
    AccountTransactionContext, ResourcesMapping, TransactionExecutionInfo,
};

// InvokeFunction.
fn create_test_state() -> CachedState<DictStateReader> {
    let block_context = BlockContext::create_for_testing();

    let test_contract_class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    let test_account_class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let test_erc20_class_hash = ClassHash(stark_felt!(TEST_ERC20_CONTRACT_CLASS_HASH));
    let class_hash_to_class = HashMap::from([
        (test_account_class_hash, get_contract_class(ACCOUNT_CONTRACT_PATH)),
        (test_contract_class_hash, get_contract_class(TEST_CONTRACT_PATH)),
        (test_erc20_class_hash, get_contract_class(ERC20_CONTRACT_PATH)),
    ]);
    let test_contract_address = ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS));
    // A random address that is unlikely to equal the result of the calculation of a contract
    // address.
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
        ((test_erc20_address, test_erc20_account_balance_key), stark_felt!(actual_fee().0 as u64)),
    ]);
    CachedState::new(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        storage_view,
        ..Default::default()
    })
}

fn invoke_tx() -> InvokeTransaction {
    let entry_point_selector = get_selector("return_result");
    let execute_calldata = calldata![
        stark_felt!(TEST_CONTRACT_ADDRESS), // Contract address.
        entry_point_selector.0,             // EP selector.
        stark_felt!(1),                     // Calldata length.
        stark_felt!(2)                      // Calldata: num.
    ];

    InvokeTransaction {
        max_fee: Fee(1),
        version: TransactionVersion(stark_felt!(1)),
        sender_address: ContractAddress(patricia_key!(TEST_ACCOUNT_CONTRACT_ADDRESS)),
        calldata: execute_calldata,
        ..Default::default()
    }
}

fn actual_fee() -> Fee {
    Fee(1)
}

#[test]
fn test_invoke_tx() {
    let mut state = create_test_state();
    let block_context = BlockContext::create_for_testing();

    // Extract invoke transaction fields for testing, as the transaction execution consumes
    // the transaction.
    let invoke_tx = invoke_tx();
    let calldata = Calldata(Arc::clone(&invoke_tx.calldata.0));
    let sender_address = invoke_tx.sender_address;

    let account_tx = AccountTransaction::Invoke(invoke_tx);
    let actual_execution_info = account_tx.execute(&mut state, &block_context).unwrap();

    // Build expected validate call info.
    let expected_account_address = ContractAddress(patricia_key!(TEST_ACCOUNT_CONTRACT_ADDRESS));
    let expected_validate_call_info = CallInfo {
        call: CallEntryPoint {
            class_hash: None,
            entry_point_type: EntryPointType::External,
            entry_point_selector: get_selector(VALIDATE_ENTRY_POINT_NAME),
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
        entry_point_selector: get_selector("return_result"),
        class_hash: None,
        entry_point_type: EntryPointType::External,
        calldata: Calldata(expected_return_result_calldata.clone().into()),
        storage_address: ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS)),
        caller_address: expected_account_address,
    };
    let expected_execute_call = CallEntryPoint {
        entry_point_selector: get_selector(EXECUTE_ENTRY_POINT_NAME),
        ..expected_validate_call_info.call.clone()
    };
    let expected_return_result_retdata = Retdata(expected_return_result_calldata.into());
    let expected_execute_call_info = CallInfo {
        call: expected_execute_call,
        execution: CallExecution { retdata: Retdata(Rc::clone(&expected_return_result_retdata.0)) },
        inner_calls: vec![CallInfo {
            call: expected_return_result_call,
            execution: CallExecution { retdata: expected_return_result_retdata },
            ..Default::default()
        }],
        ..Default::default()
    };

    // Build expected fee transfer call info.
    let expected_sequencer_address = *block_context.sequencer_address.0.key();
    let expected_actual_fee = actual_fee();
    // The least significant 128 bits of the expected amount transferred.
    let lsb_expected_amount = stark_felt!(expected_actual_fee.0 as u64);
    // The most significant 128 bits of the expected amount transferred.
    let msb_expected_amount = stark_felt!(0);
    let expected_fee_transfer_call = CallEntryPoint {
        class_hash: None,
        entry_point_type: EntryPointType::External,
        entry_point_selector: get_selector(TRANSFER_ENTRY_POINT_NAME),
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
        keys: vec![EventKey(get_selector(TRANSFER_EVENT_NAME).0)],
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
    let block_context = BlockContext::create_for_testing();
    let valid_invoke_tx = invoke_tx();

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
        if (version, allowed_versions) == (invalid_tx_version, &expected_allowed_versions)
    );

    // Insufficient fee.
    let tx_max_fee = Fee(0);
    let invalid_tx = AccountTransaction::Invoke(InvokeTransaction {
        max_fee: tx_max_fee,
        ..valid_invoke_tx.clone()
    });
    let execution_error = invalid_tx.execute(&mut state, &block_context).unwrap_err();

    // Test error.
    let expected_actual_fee = actual_fee();
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

// Declare.
fn declare_tx() -> DeclareTransaction {
    DeclareTransaction {
        max_fee: Fee(1),
        version: TransactionVersion(StarkFelt::from(1)),
        class_hash: ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH)),
        sender_address: ContractAddress(patricia_key!(TEST_ACCOUNT_CONTRACT_ADDRESS)),
        ..Default::default()
    }
}

#[test]
fn test_declare_tx() {
    let mut state = create_test_state();
    let block_context = BlockContext::create_for_testing();

    let declare_tx = declare_tx();
    let account_tx_context = AccountTransactionContext::default();
    let actual_execution_info =
        declare_tx.execute_tx(&mut state, &block_context, &account_tx_context).unwrap();

    // Test execution info result.
    assert_eq!(actual_execution_info, CallInfo::default());
}

// DeployAccount.
fn deploy_account_tx() -> DeployAccountTransaction {
    let class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let deployer_address = ContractAddress::default();
    let contract_address_salt = ContractAddressSalt::default();
    let contract_address = calculate_contract_address(
        contract_address_salt,
        class_hash,
        &calldata![],
        deployer_address,
    )
    .unwrap();

    DeployAccountTransaction {
        max_fee: Fee(1),
        version: TransactionVersion(stark_felt!(1)),
        class_hash,
        contract_address,
        contract_address_salt,
        ..Default::default()
    }
}

// TODO(Noa, 25/01/23): Test DeployAccount with constructor + add negative tests.
#[test]
fn test_deploy_account_tx() {
    let mut state = create_test_state();
    let block_context = BlockContext::create_for_testing();
    // Extract deploy account transaction fields for testing, as the transaction execution consumes
    // the transaction.
    let deploy_account_tx = deploy_account_tx();
    let class_hash = deploy_account_tx.class_hash;
    let deployed_account_address = deploy_account_tx.contract_address;

    let account_tx_context = AccountTransactionContext {
        transaction_hash: deploy_account_tx.transaction_hash,
        max_fee: deploy_account_tx.max_fee,
        version: deploy_account_tx.version,
        signature: deploy_account_tx.signature.clone(),
        nonce: deploy_account_tx.nonce,
        sender_address: deployed_account_address,
    };

    let actual_execution_info =
        deploy_account_tx.execute_tx(&mut state, &block_context, &account_tx_context).unwrap();

    let expected_execute_call_info = CallInfo {
        call: CallEntryPoint {
            entry_point_type: EntryPointType::Constructor,
            entry_point_selector: get_selector(CONSTRUCTOR_ENTRY_POINT_NAME),
            storage_address: deployed_account_address,
            ..Default::default()
        },
        ..Default::default()
    };

    // Verify deployment.
    assert_eq!(actual_execution_info, expected_execute_call_info);
    let class_hash_from_state = *state.get_class_hash_at(deployed_account_address).unwrap();
    assert_eq!(class_hash_from_state, class_hash);
}
