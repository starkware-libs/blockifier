use std::collections::HashMap;
use std::sync::Arc;

use assert_matches::assert_matches;
use cairo_vm::vm::runners::builtin_runner::{HASH_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use itertools::concat;
use pretty_assertions::assert_eq;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::{EntryPointType, StorageKey};
use starknet_api::transaction::{
    Calldata, DeclareTransaction, DeployAccountTransaction, EventContent, EventData, EventKey, Fee,
    InvokeTransaction, TransactionSignature, TransactionVersion,
};
use starknet_api::{calldata, patricia_key, stark_felt};

use crate::abi::abi_utils::{get_storage_var_address, selector_from_name};
use crate::abi::constants as abi_constants;
use crate::block_context::BlockContext;
use crate::execution::entry_point::{
    CallEntryPoint, CallExecution, CallInfo, CallType, OrderedEvent, Retdata,
};
use crate::retdata;
use crate::state::cached_state::CachedState;
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::{
    get_contract_class, validate_tx_execution_info, DictStateReader, ACCOUNT_CONTRACT_PATH,
    ERC20_CONTRACT_PATH, TEST_ACCOUNT_CONTRACT_ADDRESS, TEST_ACCOUNT_CONTRACT_CLASS_HASH,
    TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS, TEST_CONTRACT_PATH, TEST_EMPTY_CONTRACT_CLASS_HASH,
    TEST_EMPTY_CONTRACT_PATH, TEST_ERC20_ACCOUNT_BALANCE_KEY, TEST_ERC20_CONTRACT_CLASS_HASH,
    TEST_ERC20_FAULTY_ACCOUNT_BALANCE_KEY, TEST_ERC20_SEQUENCER_BALANCE_KEY,
    TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS, TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH,
    TEST_FAULTY_ACCOUNT_CONTRACT_PATH,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants;
use crate::transaction::errors::{
    FeeTransferError, InvokeTransactionError, TransactionExecutionError,
};
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionInfo};
use crate::transaction::transactions::ExecutableTransaction;

// Corresponding constants to the ones in faulty_account.
pub const VALID: u64 = 0;
pub const CALL_CONTRACT: u64 = 2;

fn create_account_tx_test_state(
    account_class_hash: &str,
    account_address: &str,
    account_path: &str,
    erc20_account_balance_key: StorageKey,
    initial_account_balance: u64,
) -> CachedState<DictStateReader> {
    let block_context = BlockContext::create_for_testing();

    let test_contract_class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    let test_account_class_hash = ClassHash(stark_felt!(account_class_hash));
    let test_erc20_class_hash = ClassHash(stark_felt!(TEST_ERC20_CONTRACT_CLASS_HASH));
    let class_hash_to_class = HashMap::from([
        (test_account_class_hash, get_contract_class(account_path)),
        (test_contract_class_hash, get_contract_class(TEST_CONTRACT_PATH)),
        (test_erc20_class_hash, get_contract_class(ERC20_CONTRACT_PATH)),
    ]);
    let test_contract_address = ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS));
    // A random address that is unlikely to equal the result of the calculation of a contract
    // address.
    let test_account_address = ContractAddress(patricia_key!(account_address));
    let test_erc20_address = block_context.fee_token_address;
    let address_to_class_hash = HashMap::from([
        (test_contract_address, test_contract_class_hash),
        (test_account_address, test_account_class_hash),
        (test_erc20_address, test_erc20_class_hash),
    ]);
    let storage_view = HashMap::from([(
        (test_erc20_address, erc20_account_balance_key),
        stark_felt!(initial_account_balance),
    )]);
    CachedState::new(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        storage_view,
        ..Default::default()
    })
}

fn actual_fee() -> Fee {
    Fee(2)
}

fn expected_validate_call_info(
    class_hash: ClassHash,
    entry_point_selector_name: &str,
    calldata: Calldata,
    storage_address: ContractAddress,
) -> Option<CallInfo> {
    // Extra range check in regular (invoke) validate call, due to passing the calldata as an array.
    let n_range_checks =
        usize::from(entry_point_selector_name == constants::VALIDATE_ENTRY_POINT_NAME);
    let vm_resources = VmExecutionResources {
        n_steps: 21,
        n_memory_holes: 1,
        builtin_instance_counter: HashMap::from([(
            RANGE_CHECK_BUILTIN_NAME.to_string(),
            n_range_checks,
        )]),
    };

    Some(CallInfo {
        call: CallEntryPoint {
            class_hash: Some(class_hash),
            entry_point_type: EntryPointType::External,
            entry_point_selector: selector_from_name(entry_point_selector_name),
            calldata,
            storage_address,
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
        },
        // The account contract we use for testing has trivial `validate` functions.
        execution: CallExecution::default(),
        vm_resources,
        ..Default::default()
    })
}

fn expected_fee_transfer_call_info(
    block_context: &BlockContext,
    account_address: ContractAddress,
    actual_fee: Fee,
    vm_resources: VmExecutionResources,
) -> Option<CallInfo> {
    let expected_fee_token_class_hash = ClassHash(stark_felt!(TEST_ERC20_CONTRACT_CLASS_HASH));
    let expected_sequencer_address = *block_context.sequencer_address.0.key();
    // The least significant 128 bits of the expected amount transferred.
    let lsb_expected_amount = stark_felt!(actual_fee.0 as u64);
    // The most significant 128 bits of the expected amount transferred.
    let msb_expected_amount = stark_felt!(0);
    let expected_fee_transfer_call = CallEntryPoint {
        class_hash: Some(expected_fee_token_class_hash),
        entry_point_type: EntryPointType::External,
        entry_point_selector: selector_from_name(constants::TRANSFER_ENTRY_POINT_NAME),
        calldata: calldata![
            expected_sequencer_address, // Recipient.
            lsb_expected_amount,
            msb_expected_amount
        ],
        storage_address: block_context.fee_token_address,
        caller_address: account_address,
        call_type: CallType::Call,
    };
    let expected_fee_sender_address = *account_address.0.key();
    let expected_fee_transfer_event = OrderedEvent {
        order: 0,
        event: EventContent {
            keys: vec![EventKey(selector_from_name(constants::TRANSFER_EVENT_NAME).0)],
            data: EventData(vec![
                expected_fee_sender_address,
                expected_sequencer_address, // Recipient.
                lsb_expected_amount,
                msb_expected_amount,
            ]),
        },
    };

    Some(CallInfo {
        call: expected_fee_transfer_call,
        execution: CallExecution {
            retdata: retdata![stark_felt!(true as u64)],
            events: vec![expected_fee_transfer_event],
            ..Default::default()
        },
        vm_resources,
        ..Default::default()
    })
}

fn validate_final_balances(
    state: &mut CachedState<DictStateReader>,
    block_context: &BlockContext,
    expected_sequencer_balance: StarkFelt,
    erc20_account_balance_key: StorageKey,
) {
    // We currently assume the total fee charged for the transaction is equal to the initial balance
    // of the account.
    let expected_account_balance = stark_felt!(0);
    let account_balance =
        state.get_storage_at(block_context.fee_token_address, erc20_account_balance_key).unwrap();
    assert_eq!(account_balance, expected_account_balance);

    assert_eq!(
        state
            .get_storage_at(block_context.fee_token_address, *TEST_ERC20_SEQUENCER_BALANCE_KEY)
            .unwrap(),
        stark_felt!(expected_sequencer_balance)
    );
}

fn invoke_tx() -> InvokeTransaction {
    let entry_point_selector = selector_from_name("return_result");
    let execute_calldata = calldata![
        stark_felt!(TEST_CONTRACT_ADDRESS), // Contract address.
        entry_point_selector.0,             // EP selector.
        stark_felt!(1),                     // Calldata length.
        stark_felt!(2)                      // Calldata: num.
    ];

    crate::test_utils::invoke_tx(
        execute_calldata,
        ContractAddress(patricia_key!(TEST_ACCOUNT_CONTRACT_ADDRESS)),
        Fee(2),
        None,
    )
}

fn create_state_with_trivial_validation_account() -> CachedState<DictStateReader> {
    let account_balance = actual_fee().0 as u64;
    create_account_tx_test_state(
        TEST_ACCOUNT_CONTRACT_CLASS_HASH,
        TEST_ACCOUNT_CONTRACT_ADDRESS,
        ACCOUNT_CONTRACT_PATH,
        *TEST_ERC20_ACCOUNT_BALANCE_KEY,
        account_balance,
    )
}

fn create_state_with_falliable_validation_account() -> CachedState<DictStateReader> {
    let account_balance = actual_fee().0 as u64;
    create_account_tx_test_state(
        TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH,
        TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS,
        TEST_FAULTY_ACCOUNT_CONTRACT_PATH,
        *TEST_ERC20_FAULTY_ACCOUNT_BALANCE_KEY,
        account_balance * 2,
    )
}

#[test]
fn test_invoke_tx() {
    let state = &mut create_state_with_trivial_validation_account();
    let block_context = &BlockContext::create_for_testing();
    let invoke_tx = invoke_tx();

    // Extract invoke transaction fields for testing, as it is consumed when creating an account
    // transaction.
    let calldata = Calldata(Arc::clone(&invoke_tx.calldata.0));
    let sender_address = invoke_tx.sender_address;

    let account_tx = AccountTransaction::Invoke(invoke_tx);
    let actual_execution_info = account_tx.execute(state, block_context).unwrap();

    // Build expected validate call info.
    let expected_account_class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let expected_account_address = ContractAddress(patricia_key!(TEST_ACCOUNT_CONTRACT_ADDRESS));
    let expected_validate_call_info = expected_validate_call_info(
        expected_account_class_hash,
        constants::VALIDATE_ENTRY_POINT_NAME,
        calldata,
        expected_account_address,
    );

    // Build expected execute call info.
    let expected_return_result_calldata = vec![stark_felt!(2)];
    let expected_return_result_call = CallEntryPoint {
        entry_point_selector: selector_from_name("return_result"),
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        entry_point_type: EntryPointType::External,
        calldata: Calldata(expected_return_result_calldata.clone().into()),
        storage_address: ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS)),
        caller_address: expected_account_address,
        call_type: CallType::Call,
    };
    let expected_execute_call = CallEntryPoint {
        entry_point_selector: selector_from_name(constants::EXECUTE_ENTRY_POINT_NAME),
        ..expected_validate_call_info.as_ref().unwrap().call.clone()
    };
    let expected_return_result_retdata = Retdata(expected_return_result_calldata);
    let expected_execute_call_info = Some(CallInfo {
        call: expected_execute_call,
        execution: CallExecution::from_retdata(Retdata(expected_return_result_retdata.0.clone())),
        vm_resources: VmExecutionResources {
            n_steps: 39,
            n_memory_holes: 1,
            builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 1)]),
        },
        inner_calls: vec![CallInfo {
            call: expected_return_result_call,
            execution: CallExecution::from_retdata(expected_return_result_retdata),
            vm_resources: VmExecutionResources {
                n_steps: 22,
                n_memory_holes: 1,
                ..Default::default()
            },
            ..Default::default()
        }],
        ..Default::default()
    });

    // Build expected fee transfer call info.
    let expected_actual_fee = actual_fee();
    let expected_fee_transfer_call_info = expected_fee_transfer_call_info(
        block_context,
        expected_account_address,
        expected_actual_fee,
        VmExecutionResources {
            n_steps: 525,
            n_memory_holes: 60,
            builtin_instance_counter: HashMap::from([
                (HASH_BUILTIN_NAME.to_string(), 4),
                (RANGE_CHECK_BUILTIN_NAME.to_string(), 21),
            ]),
        },
    );

    let expected_execution_info = TransactionExecutionInfo {
        validate_call_info: expected_validate_call_info,
        execute_call_info: expected_execute_call_info,
        fee_transfer_call_info: expected_fee_transfer_call_info,
        actual_fee: expected_actual_fee,
        actual_resources: ResourcesMapping::default(),
        n_storage_updates: 0,
        n_modified_contracts: 0,
        n_class_updates: 0,
    };

    // Test execution info result.
    validate_tx_execution_info(actual_execution_info, expected_execution_info);

    // Test nonce update.
    let nonce_from_state = state.get_nonce_at(sender_address).unwrap();
    assert_eq!(nonce_from_state, Nonce(stark_felt!(1)));

    // Test final balances.
    let expected_sequencer_balance = stark_felt!(expected_actual_fee.0 as u64);
    validate_final_balances(
        state,
        block_context,
        expected_sequencer_balance,
        *TEST_ERC20_ACCOUNT_BALANCE_KEY,
    );
}

#[test]
fn test_negative_invoke_tx_flows() {
    let state = &mut create_state_with_trivial_validation_account();
    let block_context = &BlockContext::create_for_testing();
    let valid_invoke_tx = invoke_tx();

    // Invalid version.
    // Note: there is no need to test for a negative version, as it cannot be constructed.
    let invalid_tx_version = TransactionVersion(stark_felt!(0));
    let invalid_tx = AccountTransaction::Invoke(InvokeTransaction {
        version: invalid_tx_version,
        ..valid_invoke_tx.clone()
    });
    let execution_error = invalid_tx.execute(state, block_context).unwrap_err();

    // Test error.
    let expected_allowed_versions = vec![TransactionVersion(stark_felt!(1))];
    assert_matches!(
        execution_error,
        TransactionExecutionError::InvalidVersion { version, allowed_versions }
        if (version, &allowed_versions) == (invalid_tx_version, &expected_allowed_versions)
    );

    // Insufficient fee.
    let invalid_max_fee = Fee(1);
    let invalid_tx = AccountTransaction::Invoke(InvokeTransaction {
        max_fee: invalid_max_fee,
        ..valid_invoke_tx.clone()
    });
    let execution_error = invalid_tx.execute(state, block_context).unwrap_err();

    // Test error.
    let expected_actual_fee = actual_fee();
    assert_matches!(
        execution_error,
        TransactionExecutionError::FeeTransferError(FeeTransferError::MaxFeeExceeded {
            max_fee,
            actual_fee,
        })
        if (max_fee, actual_fee) == (invalid_max_fee, expected_actual_fee)
    );

    // Invalid selector.
    let invalid_selector = Some(EntryPointSelector::default());
    let invalid_tx = AccountTransaction::Invoke(InvokeTransaction {
        entry_point_selector: invalid_selector,
        ..valid_invoke_tx.clone()
    });
    let execution_error = invalid_tx
        .execute(&mut create_state_with_trivial_validation_account(), block_context)
        .unwrap_err();

    // Test error.
    assert_matches!(
        execution_error,
        TransactionExecutionError::InvokeTransactionError(
            InvokeTransactionError::SpecifiedEntryPoint
        )
    );

    // Invalid nonce.
    // Use a fresh state to facilitate testing.
    let invalid_nonce = Nonce(stark_felt!(1));
    let invalid_tx =
        AccountTransaction::Invoke(InvokeTransaction { nonce: invalid_nonce, ..valid_invoke_tx });
    let execution_error = invalid_tx
        .execute(&mut create_state_with_trivial_validation_account(), block_context)
        .unwrap_err();

    // Test error.
    assert_matches!(
        execution_error,
        TransactionExecutionError::InvalidNonce { expected_nonce, actual_nonce }
        if (expected_nonce, actual_nonce) == (Nonce::default(), invalid_nonce)
    );
}

fn declare_tx() -> DeclareTransaction {
    crate::test_utils::declare_tx(
        TEST_EMPTY_CONTRACT_CLASS_HASH,
        ContractAddress(patricia_key!(TEST_ACCOUNT_CONTRACT_ADDRESS)),
        Fee(2),
    )
}

#[test]
fn test_declare_tx() {
    let state = &mut create_state_with_trivial_validation_account();
    let block_context = &BlockContext::create_for_testing();
    let declare_tx = declare_tx();

    // Extract declare transaction fields for testing, as it is consumed when creating an account
    // transaction.
    let sender_address = declare_tx.sender_address;
    let class_hash = declare_tx.class_hash;

    let contract_class = get_contract_class(TEST_EMPTY_CONTRACT_PATH);
    let account_tx = AccountTransaction::Declare(declare_tx.clone(), contract_class.clone());

    // Check state before transaction application.
    assert_matches!(
        state.get_contract_class(&class_hash).unwrap_err(),
        StateError::UndeclaredClassHash(undeclared_class_hash) if
        undeclared_class_hash == class_hash
    );
    let actual_execution_info = account_tx.execute(state, block_context).unwrap();

    // Build expected validate call info.
    let expected_account_class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let expected_account_address = ContractAddress(patricia_key!(TEST_ACCOUNT_CONTRACT_ADDRESS));
    let expected_validate_call_info = expected_validate_call_info(
        expected_account_class_hash,
        constants::VALIDATE_DECLARE_ENTRY_POINT_NAME,
        calldata![class_hash.0],
        expected_account_address,
    );

    // Build expected fee transfer call info.
    let expected_actual_fee = actual_fee();
    let expected_fee_transfer_call_info = expected_fee_transfer_call_info(
        block_context,
        expected_account_address,
        expected_actual_fee,
        VmExecutionResources {
            n_steps: 525,
            n_memory_holes: 60,
            builtin_instance_counter: HashMap::from([
                (RANGE_CHECK_BUILTIN_NAME.to_string(), 21),
                (HASH_BUILTIN_NAME.to_string(), 4),
            ]),
        },
    );

    let expected_execution_info = TransactionExecutionInfo {
        validate_call_info: expected_validate_call_info,
        execute_call_info: None,
        fee_transfer_call_info: expected_fee_transfer_call_info,
        actual_fee: expected_actual_fee,
        actual_resources: ResourcesMapping::default(),
        n_storage_updates: 0,
        n_modified_contracts: 0,
        n_class_updates: 0,
    };

    // Test execution info result.
    validate_tx_execution_info(actual_execution_info, expected_execution_info);

    // Test nonce update.
    let nonce_from_state = state.get_nonce_at(sender_address).unwrap();
    assert_eq!(nonce_from_state, Nonce(stark_felt!(1)));

    // Test final balances.
    let expected_sequencer_balance = stark_felt!(expected_actual_fee.0 as u64);
    validate_final_balances(
        state,
        block_context,
        expected_sequencer_balance,
        *TEST_ERC20_ACCOUNT_BALANCE_KEY,
    );

    // Verify class declaration.
    let contract_class_from_state = state.get_contract_class(&class_hash).unwrap();
    assert_eq!(contract_class_from_state, Arc::from(contract_class.clone()));

    // Negative flow: check that the same class hash cannot be declared twice.
    let invalid_declare_tx = AccountTransaction::Declare(
        DeclareTransaction { nonce: Nonce(stark_felt!(1)), ..declare_tx },
        contract_class,
    );
    let error = invalid_declare_tx.execute(state, block_context).unwrap_err();
    assert_eq!(format!("Class with hash {class_hash:?} is already declared."), format!("{error}"));
}

fn deploy_account_tx() -> DeployAccountTransaction {
    crate::test_utils::deploy_account_tx(TEST_ACCOUNT_CONTRACT_CLASS_HASH, Fee(2))
}

#[test]
fn test_deploy_account_tx() {
    let state = &mut create_state_with_trivial_validation_account();
    let block_context = &BlockContext::create_for_testing();
    let deploy_account_tx = deploy_account_tx();

    // Extract deploy account transaction fields for testing, as it is consumed when creating an
    // account transaction.
    let class_hash = deploy_account_tx.class_hash;
    let deployed_account_address = deploy_account_tx.contract_address;
    let constructor_calldata = deploy_account_tx.constructor_calldata.clone();
    let salt = deploy_account_tx.contract_address_salt;

    // Update the balance of the about to be deployed account contract in the erc20 contract, so it
    // can pay for the transaction execution.
    let expected_actual_fee = actual_fee();
    let deployed_account_balance_key =
        get_storage_var_address("ERC20_balances", &[*deployed_account_address.0.key()]).unwrap();
    state.set_storage_at(
        block_context.fee_token_address,
        deployed_account_balance_key,
        stark_felt!(expected_actual_fee.0 as u64),
    );

    let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);
    let actual_execution_info = account_tx.execute(state, block_context).unwrap();

    // Build expected validate call info.
    let validate_calldata =
        concat(vec![vec![class_hash.0, salt.0], (*constructor_calldata.0).clone()]);
    let expected_account_class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let expected_validate_call_info = expected_validate_call_info(
        expected_account_class_hash,
        constants::VALIDATE_DEPLOY_ENTRY_POINT_NAME,
        Calldata(validate_calldata.into()),
        deployed_account_address,
    );

    // Build expected execute call info.
    let expected_execute_call_info = Some(CallInfo {
        call: CallEntryPoint {
            class_hash: Some(expected_account_class_hash),
            entry_point_type: EntryPointType::Constructor,
            entry_point_selector: selector_from_name(abi_constants::CONSTRUCTOR_ENTRY_POINT_NAME),
            storage_address: deployed_account_address,
            ..Default::default()
        },
        ..Default::default()
    });

    // Build expected fee transfer call info.
    let expected_fee_transfer_call_info = expected_fee_transfer_call_info(
        block_context,
        deployed_account_address,
        expected_actual_fee,
        VmExecutionResources {
            n_steps: 525,
            n_memory_holes: 58,
            builtin_instance_counter: HashMap::from([
                (HASH_BUILTIN_NAME.to_string(), 4),
                (RANGE_CHECK_BUILTIN_NAME.to_string(), 21),
            ]),
        },
    );

    let expected_execution_info = TransactionExecutionInfo {
        validate_call_info: expected_validate_call_info,
        execute_call_info: expected_execute_call_info,
        fee_transfer_call_info: expected_fee_transfer_call_info,
        actual_fee: expected_actual_fee,
        actual_resources: ResourcesMapping::default(),
        n_storage_updates: 0,
        n_modified_contracts: 1,
        n_class_updates: 1,
    };

    // Test execution info result.
    validate_tx_execution_info(actual_execution_info, expected_execution_info);

    // Test nonce update.
    let nonce_from_state = state.get_nonce_at(deployed_account_address).unwrap();
    assert_eq!(nonce_from_state, Nonce(stark_felt!(1)));

    // Test final balances.
    let expected_sequencer_balance = stark_felt!(expected_actual_fee.0 as u64);
    validate_final_balances(
        state,
        block_context,
        expected_sequencer_balance,
        deployed_account_balance_key,
    );

    // Verify deployment.
    let class_hash_from_state = state.get_class_hash_at(deployed_account_address).unwrap();
    assert_eq!(class_hash_from_state, class_hash);
}

#[test]
fn test_validate_invoke_function() {
    let state = &mut create_state_with_falliable_validation_account();
    let block_context = &BlockContext::create_for_testing();

    fn create_tx(scenario: u64, additional_data: Option<StarkFelt>) -> InvokeTransaction {
        let entry_point_selector = selector_from_name("foo");
        let execute_calldata = calldata![
            stark_felt!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS), // Contract address.
            entry_point_selector.0,                            // EP selector.
            stark_felt!(0)                                     // Calldata length.
        ];
        // We use the signature to set the scenario. If the scenario is `CALL_CONTRACT` we also use
        // it to set the contract_address.
        let signature = TransactionSignature(vec![
            StarkFelt::from(scenario),
            additional_data.unwrap_or_else(|| StarkFelt::from(0)),
        ]);

        crate::test_utils::invoke_tx(
            execute_calldata,
            ContractAddress(patricia_key!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS)),
            Fee(2),
            Some(signature),
        )
    }

    // Positive flows.
    // Valid logic.
    let mut account_tx = AccountTransaction::Invoke(create_tx(VALID, None));
    account_tx.execute(state, block_context).unwrap();

    // Calling self (allowed).
    account_tx = AccountTransaction::Invoke(InvokeTransaction {
        nonce: Nonce(stark_felt!(1)),
        ..create_tx(CALL_CONTRACT, Some(stark_felt!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS)))
    });
    account_tx.execute(state, block_context).unwrap();
}
