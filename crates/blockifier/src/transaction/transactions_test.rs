use std::collections::{HashMap, HashSet};
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
    Calldata, DeclareTransactionV0V1, DeclareTransactionV2, EventContent, EventData, EventKey, Fee,
    InvokeTransactionV1, TransactionHash, TransactionSignature,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};
use test_case::test_case;

use crate::abi::abi_utils::{
    get_erc20_balance_var_addresses, get_storage_var_address, selector_from_name,
};
use crate::abi::constants as abi_constants;
use crate::block_context::BlockContext;
use crate::execution::call_info::{CallExecution, CallInfo, OrderedEvent, Retdata};
use crate::execution::contract_class::{ContractClass, ContractClassV0, ContractClassV1};
use crate::execution::entry_point::{CallEntryPoint, CallType};
use crate::execution::errors::EntryPointExecutionError;
use crate::fee::fee_utils::calculate_tx_fee;
use crate::fee::gas_usage::{calculate_tx_gas_usage, estimate_minimal_fee};
use crate::retdata;
use crate::state::cached_state::{CachedState, StateChangesCount};
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::{
    test_erc20_account_balance_key, test_erc20_sequencer_balance_key, DictStateReader,
    NonceManager, BALANCE, MAX_FEE, TEST_ACCOUNT_CONTRACT_ADDRESS,
    TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS,
    TEST_EMPTY_CONTRACT_CAIRO0_PATH, TEST_EMPTY_CONTRACT_CAIRO1_PATH,
    TEST_EMPTY_CONTRACT_CLASS_HASH, TEST_ERC20_CONTRACT_ADDRESS, TEST_ERC20_CONTRACT_CLASS_HASH,
    TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS, TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionInfo};
use crate::transaction::test_utils::{
    create_account_tx_for_validate_test, create_state_with_cairo1_account,
    create_state_with_falliable_validation_account, create_state_with_trivial_validation_account,
    CALL_CONTRACT, INVALID, VALID,
};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transactions::{
    DeclareTransaction, DeployAccountTransaction, ExecutableTransaction,
};

enum CairoVersion {
    Cairo0,
    Cairo1,
}

struct ExpectedResultTestInvokeTx {
    range_check: usize,
    n_steps: usize,
    vm_resources: VmExecutionResources,
    validate_gas_consumed: u64,
    execute_gas_consumed: u64,
    inner_call_initial_gas: u64,
}

fn expected_validate_call_info(
    class_hash: ClassHash,
    entry_point_selector_name: &str,
    gas_consumed: u64,
    calldata: Calldata,
    storage_address: ContractAddress,
    cairo_version: CairoVersion,
) -> Option<CallInfo> {
    let retdata = match cairo_version {
        CairoVersion::Cairo0 => Retdata::default(),
        CairoVersion::Cairo1 => retdata!(stark_felt!(constants::VALIDATE_RETDATA)),
    };
    // Extra range check in regular (invoke) validate call, due to passing the calldata as an array.
    let n_range_checks = match cairo_version {
        CairoVersion::Cairo0 => {
            usize::from(entry_point_selector_name == constants::VALIDATE_ENTRY_POINT_NAME)
        }
        CairoVersion::Cairo1 => {
            if entry_point_selector_name == constants::VALIDATE_ENTRY_POINT_NAME { 7 } else { 2 }
        }
    };
    let n_memory_holes = match cairo_version {
        CairoVersion::Cairo1
            if entry_point_selector_name == constants::VALIDATE_ENTRY_POINT_NAME =>
        {
            1
        }
        _ => 0,
    };
    let n_steps = match (entry_point_selector_name, cairo_version) {
        (constants::VALIDATE_DEPLOY_ENTRY_POINT_NAME, CairoVersion::Cairo0) => 13_usize,
        (constants::VALIDATE_DEPLOY_ENTRY_POINT_NAME, CairoVersion::Cairo1) => 69_usize,
        (constants::VALIDATE_DECLARE_ENTRY_POINT_NAME, CairoVersion::Cairo0) => 12_usize,
        (constants::VALIDATE_DECLARE_ENTRY_POINT_NAME, CairoVersion::Cairo1) => 50_usize,
        (constants::VALIDATE_ENTRY_POINT_NAME, CairoVersion::Cairo0) => 21_usize,
        (constants::VALIDATE_ENTRY_POINT_NAME, CairoVersion::Cairo1) => 188_usize,
        (selector, _) => panic!("Selector {selector} is not a known validate selector."),
    };
    let vm_resources = VmExecutionResources {
        n_steps,
        n_memory_holes,
        builtin_instance_counter: HashMap::from([(
            RANGE_CHECK_BUILTIN_NAME.to_string(),
            n_range_checks,
        )]),
    }
    .filter_unused_builtins();

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
            initial_gas: Transaction::initial_gas(),
        },
        // The account contract we use for testing has trivial `validate` functions.
        vm_resources,
        execution: CallExecution { retdata, gas_consumed, ..Default::default() },
        ..Default::default()
    })
}

fn expected_fee_transfer_call_info(
    block_context: &BlockContext,
    account_address: ContractAddress,
    actual_fee: Fee,
    vm_resources: VmExecutionResources,
) -> Option<CallInfo> {
    let expected_fee_token_class_hash = class_hash!(TEST_ERC20_CONTRACT_CLASS_HASH);
    let expected_sequencer_address = *block_context.sequencer_address.0.key();
    // The least significant 128 bits of the expected amount transferred.
    let lsb_expected_amount = stark_felt!(actual_fee.0);
    // The most significant 128 bits of the expected amount transferred.
    let msb_expected_amount = stark_felt!(0_u8);
    // TODO(Dori, 1/9/2023): NEW_TOKEN_SUPPORT storage address should depend on tx version(s).
    let storage_address = block_context.deprecated_fee_token_address;
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
        initial_gas: abi_constants::INITIAL_GAS_COST,
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

    let (sender_balance_key_low, sender_balance_key_high) =
        get_erc20_balance_var_addresses(&account_address).expect("Cannot get sender balance keys.");
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_erc20_balance_var_addresses(&block_context.sequencer_address)
            .expect("Cannot get sequencer balance keys.");
    Some(CallInfo {
        call: expected_fee_transfer_call,
        execution: CallExecution {
            retdata: retdata![stark_felt!(constants::FELT_TRUE)],
            events: vec![expected_fee_transfer_event],
            ..Default::default()
        },
        vm_resources,
        // We read sender balance, write (which starts with read) sender balance, then the same for
        // recipient. We read Uint256(BALANCE, 0) twice, then Uint256(0, 0) twice.
        storage_read_values: vec![
            stark_felt!(BALANCE),
            stark_felt!(0_u8),
            stark_felt!(BALANCE),
            stark_felt!(0_u8),
            stark_felt!(0_u8),
            stark_felt!(0_u8),
            stark_felt!(0_u8),
            stark_felt!(0_u8),
        ],
        accessed_storage_keys: HashSet::from_iter(vec![
            sender_balance_key_low,
            sender_balance_key_high,
            sequencer_balance_key_low,
            sequencer_balance_key_high,
        ]),
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
    // TODO(Dori, 1/9/2023): NEW_TOKEN_SUPPORT this function should probably accept fee token
    //   address (or at least, tx version) as input.
    let fee_token_address = block_context.deprecated_fee_token_address;
    let account_balance =
        state.get_storage_at(fee_token_address, erc20_account_balance_key).unwrap();
    assert_eq!(account_balance, stark_felt!(expected_account_balance));

    assert_eq!(
        state.get_storage_at(fee_token_address, test_erc20_sequencer_balance_key()).unwrap(),
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
        contract_address!(TEST_ACCOUNT_CONTRACT_ADDRESS),
        Fee(MAX_FEE),
        None,
    )
}

#[test_case(
    &mut create_state_with_trivial_validation_account(),
    ExpectedResultTestInvokeTx{
        range_check: 101,
        n_steps: 4155,
        vm_resources: VmExecutionResources {
            n_steps:  61,
            n_memory_holes:  0,
            builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 1)]),
        },
        validate_gas_consumed: 0,
        execute_gas_consumed: 0,
        inner_call_initial_gas: abi_constants::INITIAL_GAS_COST,
    },
    CairoVersion::Cairo0;
    "With Cairo0 account")]
#[test_case(
    &mut create_state_with_cairo1_account(),
    ExpectedResultTestInvokeTx{
        range_check: 113,
        n_steps: 4575,
        vm_resources: VmExecutionResources {
            n_steps: 283,
            n_memory_holes: 1,
            builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 7)]),
        },
        validate_gas_consumed: 14360, // The gas consumption results from parsing the input
            // arguments.
        execute_gas_consumed: 103660,
        inner_call_initial_gas: 9999681980,
    },
    CairoVersion::Cairo1;
    "With Cairo1 account")]
fn test_invoke_tx(
    state: &mut CachedState<DictStateReader>,
    expected_arguments: ExpectedResultTestInvokeTx,
    cairo_version: CairoVersion,
) {
    let block_context = &BlockContext::create_for_account_testing();
    let invoke_tx = invoke_tx();

    // Extract invoke transaction fields for testing, as it is consumed when creating an account
    // transaction.
    let calldata = Calldata(Arc::clone(&invoke_tx.calldata.0));
    let sender_address = invoke_tx.sender_address;

    let account_tx = AccountTransaction::Invoke(invoke_tx.into());
    let actual_execution_info = account_tx.execute(state, block_context, true, true).unwrap();

    // Build expected validate call info.
    let expected_account_class_hash = class_hash!(TEST_ACCOUNT_CONTRACT_CLASS_HASH);
    let expected_validate_call_info = expected_validate_call_info(
        expected_account_class_hash,
        constants::VALIDATE_ENTRY_POINT_NAME,
        expected_arguments.validate_gas_consumed,
        calldata,
        sender_address,
        cairo_version,
    );

    // Build expected execute call info.
    let expected_return_result_calldata = vec![stark_felt!(2_u8)];
    let storage_address = contract_address!(TEST_CONTRACT_ADDRESS);
    let expected_return_result_call = CallEntryPoint {
        entry_point_selector: selector_from_name("return_result"),
        class_hash: Some(class_hash!(TEST_CLASS_HASH)),
        code_address: Some(storage_address),
        entry_point_type: EntryPointType::External,
        calldata: Calldata(expected_return_result_calldata.clone().into()),
        storage_address,
        caller_address: sender_address,
        call_type: CallType::Call,
        initial_gas: expected_arguments.inner_call_initial_gas,
    };
    let expected_execute_call = CallEntryPoint {
        entry_point_selector: selector_from_name(constants::EXECUTE_ENTRY_POINT_NAME),
        initial_gas: Transaction::initial_gas() - expected_arguments.validate_gas_consumed,
        ..expected_validate_call_info.as_ref().unwrap().call.clone()
    };
    let expected_return_result_retdata = Retdata(expected_return_result_calldata);
    let expected_execute_call_info = Some(CallInfo {
        call: expected_execute_call,
        execution: CallExecution {
            retdata: Retdata(expected_return_result_retdata.0.clone()),
            gas_consumed: expected_arguments.execute_gas_consumed,
            ..Default::default()
        },
        vm_resources: expected_arguments.vm_resources,
        inner_calls: vec![CallInfo {
            call: expected_return_result_call,
            execution: CallExecution::from_retdata(expected_return_result_retdata),
            vm_resources: VmExecutionResources {
                n_steps: 22,
                n_memory_holes: 0,
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
        sender_address,
        expected_actual_fee,
        VmExecutionResources {
            n_steps: 525,
            n_memory_holes: 59,
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
            // 1 modified contract, 1 storage update (sender balance).
            (abi_constants::GAS_USAGE.to_string(), (2 + 2) * 612),
            (HASH_BUILTIN_NAME.to_string(), 16),
            (RANGE_CHECK_BUILTIN_NAME.to_string(), expected_arguments.range_check),
            (abi_constants::N_STEPS_RESOURCE.to_string(), expected_arguments.n_steps),
        ])),
        revert_error: None,
    };

    // Test execution info result.
    assert_eq!(actual_execution_info, expected_execution_info);

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

#[test_case(
    &mut create_state_with_trivial_validation_account();
    "With Cairo0 account")]
#[test_case(
    &mut create_state_with_cairo1_account();
    "With Cairo1 account")]
fn test_state_get_fee_token_balance(state: &mut CachedState<DictStateReader>) {
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
        contract_address!(TEST_ACCOUNT_CONTRACT_ADDRESS),
        Fee(MAX_FEE),
        None,
    );
    AccountTransaction::Invoke(mint_tx.into()).execute(state, block_context, true, true).unwrap();

    // Get balance from state, and validate.
    let (low, high) =
        state.get_fee_token_balance(block_context, &contract_address!(recipient)).unwrap();

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
        invalid_tx.execute(state, block_context, true, true).unwrap_err(),
        TransactionExecutionError::MaxFeeExceedsBalance{ max_fee, .. }
        if max_fee == sent_max_fee
    );
}

#[test_case(
    &mut create_state_with_trivial_validation_account();
    "With Cairo0 account")]
#[test_case(
    &mut create_state_with_cairo1_account();
    "With Cairo1 account")]
fn test_max_fee_exceeds_balance(state: &mut CachedState<DictStateReader>) {
    let block_context = &BlockContext::create_for_account_testing();
    let invalid_max_fee = Fee(BALANCE + 1);

    // Invoke.
    let invalid_tx = AccountTransaction::Invoke(
        InvokeTransactionV1 { max_fee: invalid_max_fee, ..invoke_tx() }.into(),
    );
    assert_failure_if_max_fee_exceeds_balance(state, block_context, invalid_tx);

    // Deploy.
    let invalid_tx = AccountTransaction::DeployAccount(deploy_account_tx(
        TEST_ACCOUNT_CONTRACT_CLASS_HASH,
        None,
        None,
        &mut NonceManager::default(),
    ));
    assert_failure_if_max_fee_exceeds_balance(state, block_context, invalid_tx);

    // Declare.
    let invalid_tx = AccountTransaction::Declare(DeclareTransaction {
        tx: starknet_api::transaction::DeclareTransaction::V1(DeclareTransactionV0V1 {
            max_fee: invalid_max_fee,
            ..declare_tx(TEST_EMPTY_CONTRACT_CLASS_HASH, TEST_ACCOUNT_CONTRACT_ADDRESS, None)
        }),
        tx_hash: TransactionHash::default(),
        contract_class: ContractClass::V0(ContractClassV0::from_file(
            TEST_EMPTY_CONTRACT_CAIRO0_PATH,
        )),
    });
    assert_failure_if_max_fee_exceeds_balance(state, block_context, invalid_tx);
}

#[test_case(
    &mut create_state_with_trivial_validation_account();
    "With Cairo0 account")]
#[test_case(
    &mut create_state_with_cairo1_account();
    "With Cairo1 account")]
fn test_negative_invoke_tx_flows(state: &mut CachedState<DictStateReader>) {
    let block_context = &BlockContext::create_for_account_testing();
    let valid_invoke_tx = invoke_tx();
    let valid_account_tx = AccountTransaction::Invoke(valid_invoke_tx.clone().into());

    // Fee too low (lower than minimal estimated fee).
    let minimal_fee = estimate_minimal_fee(block_context, &valid_account_tx).unwrap();
    let invalid_max_fee = Fee(minimal_fee.0 - 1);
    let invalid_tx = AccountTransaction::Invoke(
        InvokeTransactionV1 { max_fee: invalid_max_fee, ..valid_invoke_tx.clone() }.into(),
    );
    let execution_error = invalid_tx.execute(state, block_context, true, true).unwrap_err();

    // Test error.
    assert_matches!(
        execution_error,
        TransactionExecutionError::MaxFeeTooLow{ min_fee, max_fee }
        if max_fee == invalid_max_fee && min_fee == minimal_fee
    );

    // Insufficient fee.
    let invalid_max_fee = minimal_fee;
    let invalid_tx = AccountTransaction::Invoke(
        InvokeTransactionV1 { max_fee: invalid_max_fee, ..valid_invoke_tx.clone() }.into(),
    );
    let execution_result = invalid_tx.execute(state, block_context, true, true).unwrap();
    let execution_error = execution_result.revert_error.unwrap();

    // Test error.
    assert!(execution_error.starts_with("Insufficient max fee:"));
    // Test that fee was charged.
    assert_eq!(execution_result.actual_fee, invalid_max_fee);

    // Invalid nonce.
    // Use a fresh state to facilitate testing.
    let invalid_nonce = Nonce(stark_felt!(1_u8));
    let invalid_tx = AccountTransaction::Invoke(
        InvokeTransactionV1 { nonce: invalid_nonce, ..valid_invoke_tx }.into(),
    );
    let execution_error = invalid_tx
        .execute(&mut create_state_with_trivial_validation_account(), block_context, true, true)
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
        contract_address!(sender_address),
        Fee(MAX_FEE),
        signature,
    )
}

#[test_case(
    &mut create_state_with_trivial_validation_account(),
    63, // range_check_builtin
    2723, // n_steps
    CairoVersion::Cairo0;
    "With Cairo0 account")]
#[test_case(
    &mut create_state_with_cairo1_account(),
    65, // range_check_builtin
    2761, // n_steps
    CairoVersion::Cairo1;
    "With Cairo1 account")]
fn test_declare_tx(
    state: &mut CachedState<DictStateReader>,
    expected_range_check_builtin: usize,
    expected_n_steps_resource: usize,
    cairo_version: CairoVersion,
) {
    let block_context = &BlockContext::create_for_account_testing();
    let declare_tx =
        declare_tx(TEST_EMPTY_CONTRACT_CLASS_HASH, TEST_ACCOUNT_CONTRACT_ADDRESS, None);

    // Extract declare transaction fields for testing, as it is consumed when creating an account
    // transaction.
    let sender_address = declare_tx.sender_address;
    let class_hash = declare_tx.class_hash;

    let contract_class =
        ContractClass::V0(ContractClassV0::from_file(TEST_EMPTY_CONTRACT_CAIRO0_PATH));
    let account_tx = AccountTransaction::Declare(DeclareTransaction {
        tx: starknet_api::transaction::DeclareTransaction::V1(declare_tx),
        tx_hash: TransactionHash::default(),
        contract_class: contract_class.clone(),
    });

    // Check state before transaction application.
    assert_matches!(
        state.get_compiled_contract_class(&class_hash).unwrap_err(),
        StateError::UndeclaredClassHash(undeclared_class_hash) if
        undeclared_class_hash == class_hash
    );
    let actual_execution_info = account_tx.execute(state, block_context, true, true).unwrap();

    // Build expected validate call info.
    let expected_account_class_hash = class_hash!(TEST_ACCOUNT_CONTRACT_CLASS_HASH);
    let expected_account_address = contract_address!(TEST_ACCOUNT_CONTRACT_ADDRESS);
    let expected_gas_consumed = 0;
    let expected_validate_call_info = expected_validate_call_info(
        expected_account_class_hash,
        constants::VALIDATE_DECLARE_ENTRY_POINT_NAME,
        expected_gas_consumed,
        calldata![class_hash.0],
        expected_account_address,
        cairo_version,
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
            n_memory_holes: 59,
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
        revert_error: None,
        actual_resources: ResourcesMapping(HashMap::from([
            // 1 modified contract, 1 storage update (sender balance).
            (abi_constants::GAS_USAGE.to_string(), (2 + 2) * 612),
            (HASH_BUILTIN_NAME.to_string(), 15),
            (RANGE_CHECK_BUILTIN_NAME.to_string(), expected_range_check_builtin),
            (abi_constants::N_STEPS_RESOURCE.to_string(), expected_n_steps_resource),
        ])),
    };

    // Test execution info result.
    assert_eq!(actual_execution_info, expected_execution_info);

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

// TODO(Noa, 01/07/23): Consider unify the decalre tx tests.
#[test]
fn test_declare_tx_v2() {
    let state = &mut create_state_with_cairo1_account();
    let block_context = &BlockContext::create_for_account_testing();
    let class_hash = class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH);
    let sender_address = contract_address!(TEST_ACCOUNT_CONTRACT_ADDRESS);
    let declare_tx = DeclareTransactionV2 {
        max_fee: Fee(MAX_FEE),
        class_hash,
        sender_address,
        ..Default::default()
    };

    let contract_class =
        ContractClass::V1(ContractClassV1::from_file(TEST_EMPTY_CONTRACT_CAIRO1_PATH));
    let account_tx = AccountTransaction::Declare(DeclareTransaction {
        tx: starknet_api::transaction::DeclareTransaction::V2(declare_tx),
        tx_hash: TransactionHash::default(),
        contract_class: contract_class.clone(),
    });

    // Check state before transaction application.
    assert_matches!(
        state.get_compiled_contract_class(&class_hash).unwrap_err(),
        StateError::UndeclaredClassHash(undeclared_class_hash) if
        undeclared_class_hash == class_hash
    );
    let actual_execution_info = account_tx.execute(state, block_context, true, true).unwrap();

    let expected_actual_resources = ResourcesMapping(HashMap::from([
        // 1 modified contract, 1 storage update (sender balance) + 1 compiled_class_hash update.
        (abi_constants::GAS_USAGE.to_string(), (2 + 2 + 2) * 612),
        (HASH_BUILTIN_NAME.to_string(), 15),
        (RANGE_CHECK_BUILTIN_NAME.to_string(), 65),
        (abi_constants::N_STEPS_RESOURCE.to_string(), 2761),
    ]));

    let expected_actual_fee =
        calculate_tx_fee(&actual_execution_info.actual_resources, block_context).unwrap();

    assert_eq!(expected_actual_resources, actual_execution_info.actual_resources);
    assert_eq!(expected_actual_fee, actual_execution_info.actual_fee);

    // Verify class declaration.
    let contract_class_from_state = state.get_compiled_contract_class(&class_hash).unwrap();
    assert_eq!(contract_class_from_state, contract_class);
}

fn deploy_account_tx(
    account_class_hash: &str,
    constructor_calldata: Option<Calldata>,
    signature: Option<TransactionSignature>,
    nonce_manager: &mut NonceManager,
) -> DeployAccountTransaction {
    crate::test_utils::deploy_account_tx(
        account_class_hash,
        Fee(MAX_FEE),
        constructor_calldata,
        signature,
        nonce_manager,
    )
}

#[test_case(
    &mut create_state_with_trivial_validation_account(),
    83, // range_check_builtin
    3641, // n_steps
    CairoVersion::Cairo0;
    "With Cairo0 account")]
#[test_case(
    &mut create_state_with_cairo1_account(),
    85, // range_check_builtin
    3697, // n_steps
    CairoVersion::Cairo1;
    "With Cairo1 account")]
fn test_deploy_account_tx(
    state: &mut CachedState<DictStateReader>,
    expected_range_check_builtin: usize,
    expected_n_steps_resource: usize,
    cairo_version: CairoVersion,
) {
    let block_context = &BlockContext::create_for_account_testing();
    // TODO(Dori, 1/9/2023): NEW_TOKEN_SUPPORT fee token address should depend on tx version.
    let fee_token_address = block_context.deprecated_fee_token_address;
    let mut nonce_manager = NonceManager::default();
    let deploy_account =
        deploy_account_tx(TEST_ACCOUNT_CONTRACT_CLASS_HASH, None, None, &mut nonce_manager);

    // Extract deploy account transaction fields for testing, as it is consumed when creating an
    // account transaction.
    let class_hash = deploy_account.class_hash();
    let deployed_account_address = deploy_account.contract_address;
    let constructor_calldata = deploy_account.constructor_calldata();
    let salt = deploy_account.contract_address_salt();

    // Update the balance of the about to be deployed account contract in the erc20 contract, so it
    // can pay for the transaction execution.
    let deployed_account_balance_key =
        get_storage_var_address("ERC20_balances", &[*deployed_account_address.0.key()]).unwrap();
    state.set_storage_at(fee_token_address, deployed_account_balance_key, stark_felt!(BALANCE));

    let account_tx = AccountTransaction::DeployAccount(deploy_account);
    let actual_execution_info = account_tx.execute(state, block_context, true, true).unwrap();

    // Build expected validate call info.
    let validate_calldata =
        concat(vec![vec![class_hash.0, salt.0], (*constructor_calldata.0).clone()]);
    let expected_account_class_hash = class_hash!(TEST_ACCOUNT_CONTRACT_CLASS_HASH);
    let expected_gas_consumed = 0;
    let expected_validate_call_info = expected_validate_call_info(
        expected_account_class_hash,
        constants::VALIDATE_DEPLOY_ENTRY_POINT_NAME,
        expected_gas_consumed,
        Calldata(validate_calldata.into()),
        deployed_account_address,
        cairo_version,
    );

    // Build expected execute call info.
    let expected_execute_call_info = Some(CallInfo {
        call: CallEntryPoint {
            class_hash: Some(expected_account_class_hash),
            code_address: None,
            entry_point_type: EntryPointType::Constructor,
            entry_point_selector: selector_from_name(abi_constants::CONSTRUCTOR_ENTRY_POINT_NAME),
            storage_address: deployed_account_address,
            initial_gas: Transaction::initial_gas(),
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
            n_steps: 529,
            n_memory_holes: 57,
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
        revert_error: None,
        actual_resources: ResourcesMapping(HashMap::from([
            // 1 modified contract, 1 storage update (sender balance) + 1 class_hash update.
            (abi_constants::GAS_USAGE.to_string(), (2 + 2 + 1) * 612),
            (HASH_BUILTIN_NAME.to_string(), 23),
            (RANGE_CHECK_BUILTIN_NAME.to_string(), expected_range_check_builtin),
            (abi_constants::N_STEPS_RESOURCE.to_string(), expected_n_steps_resource),
        ])),
    };

    // Test execution info result.
    assert_eq!(actual_execution_info, expected_execution_info);

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
    let deploy_account =
        deploy_account_tx(TEST_ACCOUNT_CONTRACT_CLASS_HASH, None, None, &mut nonce_manager);
    let account_tx = AccountTransaction::DeployAccount(deploy_account);
    let error = account_tx.execute(state, block_context, true, true).unwrap_err();
    assert_matches!(
        error,
        TransactionExecutionError::ContractConstructorExecutionFailed(
            EntryPointExecutionError::StateError(StateError::UnavailableContractAddress(_))
        )
    );
}

#[test]
fn test_validate_accounts_tx() {
    fn test_validate_account_tx(tx_type: TransactionType) {
        let block_context = &BlockContext::create_for_account_testing();

        // Positive flows.
        // Valid logic.
        let state = &mut create_state_with_falliable_validation_account();
        let account_tx =
            create_account_tx_for_validate_test(tx_type, VALID, None, &mut NonceManager::default());
        account_tx.execute(state, block_context, true, true).unwrap();

        if tx_type != TransactionType::DeployAccount {
            // Calling self (allowed).
            let state = &mut create_state_with_falliable_validation_account();
            let account_tx = create_account_tx_for_validate_test(
                tx_type,
                CALL_CONTRACT,
                Some(stark_felt!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS)),
                &mut NonceManager::default(),
            );
            account_tx.execute(state, block_context, true, true).unwrap();
        }

        // Negative flows.

        // Logic failure.
        let state = &mut create_state_with_falliable_validation_account();
        let account_tx = create_account_tx_for_validate_test(
            tx_type,
            INVALID,
            None,
            &mut NonceManager::default(),
        );
        let error = account_tx.execute(state, block_context, true, true).unwrap_err();
        // TODO(Noa,01/05/2023): Test the exact failure reason.
        assert_matches!(error, TransactionExecutionError::ValidateTransactionError(_));

        // Trying to call another contract (forbidden).
        let account_tx = create_account_tx_for_validate_test(
            tx_type,
            CALL_CONTRACT,
            Some(stark_felt!(TEST_CONTRACT_ADDRESS)),
            &mut NonceManager::default(),
        );
        let error = account_tx.execute(state, block_context, true, true).unwrap_err();
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
                &mut NonceManager::default(),
            );
            let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);
            let error = account_tx.execute(state, block_context, true, true).unwrap_err();
            assert_matches!(error, TransactionExecutionError::UnauthorizedInnerCall{entry_point_kind} if
        entry_point_kind == "an account constructor");
        }
    }

    test_validate_account_tx(TransactionType::InvokeFunction);
    test_validate_account_tx(TransactionType::Declare);
    test_validate_account_tx(TransactionType::DeployAccount);
}

// Test that we exclude the fee token contract modification and adds the account’s balance change
// in the state changes.
#[test]
fn test_calculate_tx_gas_usage() {
    let state = &mut create_state_with_trivial_validation_account();
    let block_context = &BlockContext::create_for_account_testing();
    // TODO(Dori, 1/9/2023): NEW_TOKEN_SUPPORT fee token address should depend on tx version.
    let fee_token_address = *block_context.deprecated_fee_token_address.0.key();

    let invoke_tx = invoke_tx();
    let account_tx = AccountTransaction::Invoke(invoke_tx.into());
    let tx_execution_info = account_tx.execute(state, block_context, true, true).unwrap();

    let n_storage_updates = 1; // For the account balance update.
    let n_modified_contracts = 1;
    let state_changes_count = StateChangesCount {
        n_storage_updates,
        n_class_hash_updates: 0,
        n_modified_contracts,
        n_compiled_class_hash_updates: 0,
    };
    let l1_gas_usage = calculate_tx_gas_usage(&[], state_changes_count, None);

    assert_eq!(
        *tx_execution_info.actual_resources.0.get(abi_constants::GAS_USAGE).unwrap(),
        l1_gas_usage
    );

    // A tx that changes the account and some other balance in execute.
    let entry_point_selector = selector_from_name(constants::TRANSFER_ENTRY_POINT_NAME);
    let some_other_account_address = stark_felt!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS);
    let execute_calldata = calldata![
        fee_token_address,          // Contract address.
        entry_point_selector.0,     // EP selector.
        stark_felt!(3_u8),          // Calldata length.
        some_other_account_address, // Calldata: recipient.
        stark_felt!(2_u8),          // Calldata: lsb amount.
        stark_felt!(0_u8)           // Calldata: msb amount.
    ];

    let invoke_tx = crate::test_utils::invoke_tx(
        execute_calldata,
        contract_address!(TEST_ACCOUNT_CONTRACT_ADDRESS),
        Fee(MAX_FEE),
        None,
    );

    let account_tx = AccountTransaction::Invoke(
        InvokeTransactionV1 { nonce: Nonce(StarkFelt::from(1_u8)), ..invoke_tx }.into(),
    );

    let tx_execution_info = account_tx.execute(state, block_context, true, true).unwrap();
    // For the balance update of the sender and the recipient.
    let n_storage_updates = 2;
    // Only the account contract modification (nonce update) excluding the fee token contract.
    let n_modified_contracts = 1;
    let state_changes_count = StateChangesCount {
        n_storage_updates,
        n_class_hash_updates: 0,
        n_modified_contracts,
        n_compiled_class_hash_updates: 0,
    };
    let l1_gas_usage = calculate_tx_gas_usage(&[], state_changes_count, None);

    assert_eq!(
        *tx_execution_info.actual_resources.0.get(abi_constants::GAS_USAGE).unwrap(),
        l1_gas_usage
    );
}
