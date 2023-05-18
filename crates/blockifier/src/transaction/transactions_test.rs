use std::collections::HashMap;
use std::sync::Arc;

use assert_matches::assert_matches;
use cairo_vm::vm::runners::builtin_runner::{HASH_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use itertools::concat;
use pretty_assertions::assert_eq;
use starknet_api::core::{ClassHash, ContractAddress, Nonce, PatriciaKey};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, DeclareTransactionV0V1, DeployAccountTransaction, EventContent, EventData, EventKey,
    Fee, InvokeTransaction, InvokeTransactionV1, TransactionSignature,
};
use starknet_api::{calldata, patricia_key, stark_felt};

use crate::abi::abi_utils::{get_storage_var_address, selector_from_name};
use crate::abi::constants as abi_constants;
use crate::block_context::BlockContext;
use crate::execution::contract_class::{ContractClass, ContractClassV0};
use crate::execution::entry_point::{
    CallEntryPoint, CallExecution, CallInfo, CallType, OrderedEvent, Retdata,
};
use crate::execution::errors::EntryPointExecutionError;
use crate::fee::fee_utils::calculate_tx_fee;
use crate::retdata;
use crate::state::cached_state::CachedState;
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::{
    test_erc20_account_balance_key, test_erc20_faulty_account_balance_key,
    test_erc20_sequencer_balance_key, validate_tx_execution_info, DictStateReader,
    ACCOUNT_CONTRACT_PATH, BALANCE, ERC20_CONTRACT_PATH, MAX_FEE, TEST_ACCOUNT_CONTRACT_ADDRESS,
    TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS, TEST_CONTRACT_PATH,
    TEST_EMPTY_CONTRACT_CLASS_HASH, TEST_EMPTY_CONTRACT_PATH, TEST_ERC20_CONTRACT_ADDRESS,
    TEST_ERC20_CONTRACT_CLASS_HASH, TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS,
    TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH, TEST_FAULTY_ACCOUNT_CONTRACT_PATH,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionInfo};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transactions::{DeclareTransaction, ExecutableTransaction};

// Corresponding constants to the ones in faulty_account.
pub const VALID: u64 = 0;
pub const INVALID: u64 = 1;
pub const CALL_CONTRACT: u64 = 2;

fn create_account_tx_test_state(
    account_class_hash: &str,
    account_address: &str,
    account_path: &str,
    erc20_account_balance_key: StorageKey,
    initial_account_balance: u128,
) -> CachedState<DictStateReader> {
    let block_context = BlockContext::create_for_testing();

    let test_contract_class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    let test_account_class_hash = ClassHash(stark_felt!(account_class_hash));
    let test_erc20_class_hash = ClassHash(stark_felt!(TEST_ERC20_CONTRACT_CLASS_HASH));
    let class_hash_to_class = HashMap::from([
        (test_account_class_hash, ContractClassV0::from_file(account_path).into()),
        (test_contract_class_hash, ContractClassV0::from_file(TEST_CONTRACT_PATH).into()),
        (test_erc20_class_hash, ContractClassV0::from_file(ERC20_CONTRACT_PATH).into()),
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
    let minter_var_address = get_storage_var_address("permitted_minter", &[])
        .expect("Failed to get permitted_minter storage address.");
    let storage_view = HashMap::from([
        ((test_erc20_address, erc20_account_balance_key), stark_felt!(initial_account_balance)),
        // Give the account mint permission.
        ((test_erc20_address, minter_var_address), *test_account_address.0.key()),
    ]);
    CachedState::new(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        storage_view,
        ..Default::default()
    })
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
            code_address: None,
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
    let lsb_expected_amount = stark_felt!(actual_fee.0);
    // The most significant 128 bits of the expected amount transferred.
    let msb_expected_amount = stark_felt!(0_u8);
    let storage_address = block_context.fee_token_address;
    let expected_fee_transfer_call = CallEntryPoint {
        class_hash: Some(expected_fee_token_class_hash),
        code_address: None,
        entry_point_type: EntryPointType::External,
        entry_point_selector: selector_from_name(constants::TRANSFER_ENTRY_POINT_NAME),
        calldata: calldata![
            expected_sequencer_address, // Recipient.
            lsb_expected_amount,
            msb_expected_amount
        ],
        storage_address,
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
            retdata: retdata![stark_felt!(constants::FELT_TRUE)],
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
    expected_account_balance: u128,
) {
    let account_balance =
        state.get_storage_at(block_context.fee_token_address, erc20_account_balance_key).unwrap();
    assert_eq!(account_balance, stark_felt!(expected_account_balance));

    assert_eq!(
        state
            .get_storage_at(block_context.fee_token_address, test_erc20_sequencer_balance_key())
            .unwrap(),
        stark_felt!(expected_sequencer_balance)
    );
}

fn invoke_tx() -> InvokeTransactionV1 {
    let entry_point_selector = selector_from_name("return_result");
    let execute_calldata = calldata![
        stark_felt!(TEST_CONTRACT_ADDRESS), // Contract address.
        entry_point_selector.0,             // EP selector.
        stark_felt!(1_u8),                  // Calldata length.
        stark_felt!(2_u8)                   // Calldata: num.
    ];

    crate::test_utils::invoke_tx(
        execute_calldata,
        ContractAddress(patricia_key!(TEST_ACCOUNT_CONTRACT_ADDRESS)),
        Fee(MAX_FEE),
        None,
    )
}

fn create_state_with_trivial_validation_account() -> CachedState<DictStateReader> {
    let account_balance = BALANCE;
    create_account_tx_test_state(
        TEST_ACCOUNT_CONTRACT_CLASS_HASH,
        TEST_ACCOUNT_CONTRACT_ADDRESS,
        ACCOUNT_CONTRACT_PATH,
        test_erc20_account_balance_key(),
        account_balance,
    )
}

fn create_state_with_falliable_validation_account() -> CachedState<DictStateReader> {
    let account_balance = BALANCE;
    create_account_tx_test_state(
        TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH,
        TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS,
        TEST_FAULTY_ACCOUNT_CONTRACT_PATH,
        test_erc20_faulty_account_balance_key(),
        account_balance * 2,
    )
}

#[test]
fn test_invoke_tx() {
    let state = &mut create_state_with_trivial_validation_account();
    let block_context = &BlockContext::create_for_account_testing();
    let invoke_tx = invoke_tx();

    // Extract invoke transaction fields for testing, as it is consumed when creating an account
    // transaction.
    let calldata = Calldata(Arc::clone(&invoke_tx.calldata.0));
    let sender_address = invoke_tx.sender_address;

    let account_tx = AccountTransaction::Invoke(InvokeTransaction::V1(invoke_tx));
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
    let expected_return_result_calldata = vec![stark_felt!(2_u8)];
    let storage_address = ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS));
    let expected_return_result_call = CallEntryPoint {
        entry_point_selector: selector_from_name("return_result"),
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        code_address: Some(storage_address),
        entry_point_type: EntryPointType::External,
        calldata: Calldata(expected_return_result_calldata.clone().into()),
        storage_address,
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
    let expected_actual_fee =
        calculate_tx_fee(&actual_execution_info.actual_resources, block_context).unwrap();
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
        actual_resources: ResourcesMapping(HashMap::from([
            (abi_constants::GAS_USAGE.to_string(), 1224),
            ("pedersen".to_string(), 16),
            ("range_check".to_string(), 101),
            (abi_constants::N_STEPS_RESOURCE.to_string(), 4082),
        ])),
    };

    // Test execution info result.
    validate_tx_execution_info(actual_execution_info, expected_execution_info);

    // Test nonce update.
    let nonce_from_state = state.get_nonce_at(sender_address).unwrap();
    assert_eq!(nonce_from_state, Nonce(stark_felt!(1_u8)));

    // Test final balances.
    let expected_sequencer_balance = stark_felt!(expected_actual_fee.0);
    let expected_account_balance = BALANCE - expected_actual_fee.0;
    validate_final_balances(
        state,
        block_context,
        expected_sequencer_balance,
        test_erc20_account_balance_key(),
        expected_account_balance,
    );
}

#[test]
fn test_state_get_fee_token_balance() {
    let state = &mut create_state_with_trivial_validation_account();
    let block_context = &BlockContext::create_for_account_testing();
    let (mint_high, mint_low) = (stark_felt!(54_u8), stark_felt!(39_u8));
    let recipient = stark_felt!(10_u8);

    // Mint some tokens.
    let entry_point_selector = selector_from_name("permissionedMint");
    let execute_calldata = calldata![
        stark_felt!(TEST_ERC20_CONTRACT_ADDRESS), // Contract address.
        entry_point_selector.0,                   // EP selector.
        stark_felt!(3_u8),                        // Calldata length.
        recipient,
        mint_low,
        mint_high
    ];
    let mint_tx = crate::test_utils::invoke_tx(
        execute_calldata,
        ContractAddress(patricia_key!(TEST_ACCOUNT_CONTRACT_ADDRESS)),
        Fee(MAX_FEE),
        None,
    );
    AccountTransaction::Invoke(InvokeTransaction::V1(mint_tx))
        .execute(state, block_context)
        .unwrap();

    // Get balance from state, and validate.
    let (low, high) = state
        .get_fee_token_balance(block_context, &ContractAddress(patricia_key!(recipient)))
        .unwrap();

    assert_eq!(low, mint_low);
    assert_eq!(high, mint_high);
}

fn assert_failure_if_max_fee_exceeds_balance(
    state: &mut CachedState<DictStateReader>,
    block_context: &BlockContext,
    invalid_tx: AccountTransaction,
) {
    let sent_max_fee = invalid_tx.max_fee();

    // Test error.
    assert_matches!(
        invalid_tx.execute(state, block_context).unwrap_err(),
        TransactionExecutionError::MaxFeeExceedsBalance{ max_fee, .. }
        if max_fee == sent_max_fee
    );
}

#[test]
fn test_max_fee_exceeds_balance() {
    let state = &mut create_state_with_trivial_validation_account();
    let block_context = &BlockContext::create_for_account_testing();
    let invalid_max_fee = Fee(BALANCE + 1);

    // Invoke.
    let invalid_tx = AccountTransaction::Invoke(InvokeTransaction::V1(InvokeTransactionV1 {
        max_fee: invalid_max_fee,
        ..invoke_tx()
    }));
    assert_failure_if_max_fee_exceeds_balance(state, block_context, invalid_tx);

    // Deploy.
    let invalid_tx = AccountTransaction::DeployAccount(DeployAccountTransaction {
        max_fee: invalid_max_fee,
        ..deploy_account_tx(TEST_ACCOUNT_CONTRACT_CLASS_HASH, None, None)
    });
    assert_failure_if_max_fee_exceeds_balance(state, block_context, invalid_tx);

    // Declare.
    let invalid_tx = AccountTransaction::Declare(DeclareTransaction {
        tx: starknet_api::transaction::DeclareTransaction::V1(DeclareTransactionV0V1 {
            max_fee: invalid_max_fee,
            ..declare_tx(TEST_EMPTY_CONTRACT_CLASS_HASH, TEST_ACCOUNT_CONTRACT_ADDRESS, None)
        }),
        contract_class: ContractClass::V0(ContractClassV0::from_file(TEST_EMPTY_CONTRACT_PATH)),
    });
    assert_failure_if_max_fee_exceeds_balance(state, block_context, invalid_tx);
}

#[test]
fn test_negative_invoke_tx_flows() {
    let state = &mut create_state_with_trivial_validation_account();
    let block_context = &BlockContext::create_for_account_testing();
    let valid_invoke_tx = invoke_tx();

    // Insufficient fee.
    let invalid_max_fee = Fee(1);
    let invalid_tx = AccountTransaction::Invoke(InvokeTransaction::V1(InvokeTransactionV1 {
        max_fee: invalid_max_fee,
        ..valid_invoke_tx.clone()
    }));
    let execution_error = invalid_tx.execute(state, block_context).unwrap_err();

    // Test error.
    assert_matches!(
        execution_error,
        TransactionExecutionError::FeeTransferError{ max_fee, .. }
        if max_fee == invalid_max_fee
    );

    // Invalid nonce.
    // Use a fresh state to facilitate testing.
    let invalid_nonce = Nonce(stark_felt!(1_u8));
    let invalid_tx = AccountTransaction::Invoke(InvokeTransaction::V1(InvokeTransactionV1 {
        nonce: invalid_nonce,
        ..valid_invoke_tx
    }));
    let execution_error = invalid_tx
        .execute(&mut create_state_with_trivial_validation_account(), block_context)
        .unwrap_err();

    // Test error.
    assert_matches!(
        execution_error,
        TransactionExecutionError::InvalidNonce { address, expected_nonce, actual_nonce }
        if (address, expected_nonce, actual_nonce) ==
        (valid_invoke_tx.sender_address, Nonce::default(), invalid_nonce)
    );
}

fn declare_tx(
    class_hash: &str,
    sender_address: &str,
    signature: Option<TransactionSignature>,
) -> DeclareTransactionV0V1 {
    crate::test_utils::declare_tx(
        class_hash,
        ContractAddress(patricia_key!(sender_address)),
        Fee(MAX_FEE),
        signature,
    )
}

#[test]
fn test_declare_tx() {
    let state = &mut create_state_with_trivial_validation_account();
    let block_context = &BlockContext::create_for_account_testing();
    let declare_tx =
        declare_tx(TEST_EMPTY_CONTRACT_CLASS_HASH, TEST_ACCOUNT_CONTRACT_ADDRESS, None);

    // Extract declare transaction fields for testing, as it is consumed when creating an account
    // transaction.
    let sender_address = declare_tx.sender_address;
    let class_hash = declare_tx.class_hash;

    let contract_class = ContractClass::V0(ContractClassV0::from_file(TEST_EMPTY_CONTRACT_PATH));
    let account_tx = AccountTransaction::Declare(DeclareTransaction {
        tx: starknet_api::transaction::DeclareTransaction::V1(declare_tx),
        contract_class: contract_class.clone(),
    });

    // Check state before transaction application.
    assert_matches!(
        state.get_compiled_contract_class(&class_hash).unwrap_err(),
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
    let expected_actual_fee =
        calculate_tx_fee(&actual_execution_info.actual_resources, block_context).unwrap();
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
        actual_resources: ResourcesMapping(HashMap::from([
            (abi_constants::GAS_USAGE.to_string(), 1224),
            ("pedersen".to_string(), 15),
            ("range_check".to_string(), 63),
            (abi_constants::N_STEPS_RESOURCE.to_string(), 2688),
        ])),
    };

    // Test execution info result.
    validate_tx_execution_info(actual_execution_info, expected_execution_info);

    // Test nonce update.
    let nonce_from_state = state.get_nonce_at(sender_address).unwrap();
    assert_eq!(nonce_from_state, Nonce(stark_felt!(1_u8)));

    // Test final balances.
    let expected_sequencer_balance = stark_felt!(expected_actual_fee.0);
    let expected_account_balance = BALANCE - expected_actual_fee.0;
    validate_final_balances(
        state,
        block_context,
        expected_sequencer_balance,
        test_erc20_account_balance_key(),
        expected_account_balance,
    );

    // Verify class declaration.
    let contract_class_from_state = state.get_compiled_contract_class(&class_hash).unwrap();
    assert_eq!(contract_class_from_state, contract_class);
}

fn deploy_account_tx(
    account_class_hash: &str,
    constructor_calldata: Option<Calldata>,
    signature: Option<TransactionSignature>,
) -> DeployAccountTransaction {
    crate::test_utils::deploy_account_tx(
        account_class_hash,
        Fee(MAX_FEE),
        constructor_calldata,
        signature,
    )
}

#[test]
fn test_deploy_account_tx() {
    let state = &mut create_state_with_trivial_validation_account();
    let block_context = &BlockContext::create_for_account_testing();
    let deploy_account_tx = deploy_account_tx(TEST_ACCOUNT_CONTRACT_CLASS_HASH, None, None);

    // Extract deploy account transaction fields for testing, as it is consumed when creating an
    // account transaction.
    let class_hash = deploy_account_tx.class_hash;
    let deployed_account_address = deploy_account_tx.contract_address;
    let constructor_calldata = deploy_account_tx.constructor_calldata.clone();
    let salt = deploy_account_tx.contract_address_salt;

    // Update the balance of the about to be deployed account contract in the erc20 contract, so it
    // can pay for the transaction execution.
    let deployed_account_balance_key =
        get_storage_var_address("ERC20_balances", &[*deployed_account_address.0.key()]).unwrap();
    state.set_storage_at(
        block_context.fee_token_address,
        deployed_account_balance_key,
        stark_felt!(BALANCE),
    );

    let account_tx = AccountTransaction::DeployAccount(deploy_account_tx.clone());
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
            code_address: None,
            entry_point_type: EntryPointType::Constructor,
            entry_point_selector: selector_from_name(abi_constants::CONSTRUCTOR_ENTRY_POINT_NAME),
            storage_address: deployed_account_address,
            ..Default::default()
        },
        ..Default::default()
    });

    // Build expected fee transfer call info.
    let expected_actual_fee =
        calculate_tx_fee(&actual_execution_info.actual_resources, block_context).unwrap();
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
        actual_resources: ResourcesMapping(HashMap::from([
            (abi_constants::GAS_USAGE.to_string(), 3060),
            ("pedersen".to_string(), 23),
            ("range_check".to_string(), 83),
            (abi_constants::N_STEPS_RESOURCE.to_string(), 3584),
        ])),
    };

    // Test execution info result.
    validate_tx_execution_info(actual_execution_info, expected_execution_info);

    // Test nonce update.
    let nonce_from_state = state.get_nonce_at(deployed_account_address).unwrap();
    assert_eq!(nonce_from_state, Nonce(stark_felt!(1_u8)));

    // Test final balances.
    let expected_sequencer_balance = stark_felt!(expected_actual_fee.0);
    let expected_account_balance = BALANCE - expected_actual_fee.0;
    validate_final_balances(
        state,
        block_context,
        expected_sequencer_balance,
        deployed_account_balance_key,
        expected_account_balance,
    );

    // Verify deployment.
    let class_hash_from_state = state.get_class_hash_at(deployed_account_address).unwrap();
    assert_eq!(class_hash_from_state, class_hash);

    // Negative flow.
    // Deploy to an existing address.
    let deploy_account_tx =
        DeployAccountTransaction { nonce: Nonce(stark_felt!(1_u8)), ..deploy_account_tx };
    let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);
    let error = account_tx.execute(state, block_context).unwrap_err();
    assert_matches!(
        error,
        TransactionExecutionError::ContractConstructorExecutionFailed(
            EntryPointExecutionError::StateError(StateError::UnavailableContractAddress(_))
        )
    );
}

fn create_account_tx_for_validate_test(
    tx_type: TransactionType,
    scenario: u64,
    additional_data: Option<StarkFelt>,
) -> AccountTransaction {
    // The first felt of the signature is used to set the scenario. If the scenario is
    // `CALL_CONTRACT` the second felt is used to pass the contract address.
    let signature = TransactionSignature(vec![
        StarkFelt::from(scenario),
        // Assumes the default value of StarkFelt is 0.
        additional_data.unwrap_or_default(),
    ]);

    match tx_type {
        TransactionType::Declare => {
            let contract_class =
                ContractClassV0::from_file(TEST_FAULTY_ACCOUNT_CONTRACT_PATH).into();
            let declare_tx = crate::test_utils::declare_tx(
                TEST_ACCOUNT_CONTRACT_CLASS_HASH,
                ContractAddress(patricia_key!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS)),
                Fee(0),
                Some(signature),
            );

            AccountTransaction::Declare(DeclareTransaction {
                tx: starknet_api::transaction::DeclareTransaction::V1(declare_tx),
                contract_class,
            })
        }
        TransactionType::DeployAccount => {
            let deploy_account_tx = crate::test_utils::deploy_account_tx(
                TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH,
                Fee(0),
                Some(calldata![stark_felt!(constants::FELT_FALSE)]),
                Some(signature),
            );
            AccountTransaction::DeployAccount(deploy_account_tx)
        }
        TransactionType::InvokeFunction => {
            let entry_point_selector = selector_from_name("foo");
            let execute_calldata = calldata![
                stark_felt!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS), // Contract address.
                entry_point_selector.0,                            // EP selector.
                stark_felt!(0_u8)                                  // Calldata length.
            ];
            let invoke_tx = crate::test_utils::invoke_tx(
                execute_calldata,
                ContractAddress(patricia_key!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS)),
                Fee(0),
                Some(signature),
            );
            AccountTransaction::Invoke(InvokeTransaction::V1(invoke_tx))
        }
        TransactionType::L1Handler => unimplemented!(),
    }
}
#[test]
fn test_validate_accounts_tx() {
    fn test_validate_account_tx(tx_type: TransactionType) {
        let block_context = &BlockContext::create_for_testing();

        // Positive flows.

        // Valid logic.
        let state = &mut create_state_with_falliable_validation_account();
        let account_tx = create_account_tx_for_validate_test(tx_type, VALID, None);
        account_tx.execute(state, block_context).unwrap();

        if tx_type != TransactionType::DeployAccount {
            // Calling self (allowed).
            let state = &mut create_state_with_falliable_validation_account();
            let account_tx = create_account_tx_for_validate_test(
                tx_type,
                CALL_CONTRACT,
                Some(stark_felt!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS)),
            );
            account_tx.execute(state, block_context).unwrap();
        }

        // Negative flows.

        // Logic failure.
        let state = &mut create_state_with_falliable_validation_account();
        let account_tx = create_account_tx_for_validate_test(tx_type, INVALID, None);
        let error = account_tx.execute(state, block_context).unwrap_err();
        // TODO(Noa,01/05/2023): Test the exact failure reason.
        assert_matches!(error, TransactionExecutionError::ValidateTransactionError(_));

        // Trying to call another contract (forbidden).
        let account_tx = create_account_tx_for_validate_test(
            tx_type,
            CALL_CONTRACT,
            Some(stark_felt!(TEST_CONTRACT_ADDRESS)),
        );
        let error = account_tx.execute(state, block_context).unwrap_err();
        assert_matches!(error, TransactionExecutionError::UnauthorizedInnerCall{entry_point_kind} if
        entry_point_kind == constants::VALIDATE_ENTRY_POINT_NAME);

        // Verify that the contract does not call another contract in the constructor of deploy
        // account as well.
        if tx_type == TransactionType::DeployAccount {
            // Deploy another instance of 'faulty_account' and trying to call other contract in the
            // constructor (forbidden).

            let deploy_account_tx = crate::test_utils::deploy_account_tx(
                TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH,
                Fee(0),
                Some(calldata![stark_felt!(constants::FELT_TRUE)]),
                // run faulty_validate() in the constructor.
                Some(TransactionSignature(vec![
                    stark_felt!(CALL_CONTRACT),
                    stark_felt!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS),
                ])),
            );
            let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);
            let error = account_tx.execute(state, block_context).unwrap_err();
            assert_matches!(error, TransactionExecutionError::UnauthorizedInnerCall{entry_point_kind} if
        entry_point_kind == "an account constructor");
        }
    }

    test_validate_account_tx(TransactionType::InvokeFunction);
    test_validate_account_tx(TransactionType::Declare);
    test_validate_account_tx(TransactionType::DeployAccount);
}
