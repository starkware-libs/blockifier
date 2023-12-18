use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use assert_matches::assert_matches;
use cairo_felt::Felt252;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::errors::vm_exception::VmException;
use cairo_vm::vm::runners::builtin_runner::{HASH_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use itertools::concat;
use num_traits::Pow;
use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::core::{ChainId, ClassHash, ContractAddress, EthAddress, Nonce, PatriciaKey};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, EventContent, EventData, EventKey, Fee, L2ToL1Payload,
    TransactionHash, TransactionSignature, TransactionVersion,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};
use strum::IntoEnumIterator;
use test_case::test_case;

use crate::abi::abi_utils::{
    get_fee_token_var_address, get_storage_var_address, selector_from_name,
};
use crate::abi::constants as abi_constants;
use crate::abi::sierra_types::next_storage_key;
use crate::block_context::BlockContext;
use crate::execution::call_info::{
    CallExecution, CallInfo, MessageToL1, OrderedEvent, OrderedL2ToL1Message, Retdata,
};
use crate::execution::contract_class::{ContractClass, ContractClassV0, ContractClassV1};
use crate::execution::entry_point::{CallEntryPoint, CallType};
use crate::execution::errors::{EntryPointExecutionError, VirtualMachineExecutionError};
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::eth_gas_constants;
use crate::fee::fee_utils::calculate_tx_fee;
use crate::fee::gas_usage::{calculate_tx_gas_usage, estimate_minimal_l1_gas};
use crate::state::cached_state::{CachedState, StateChangesCount};
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::cached_state::create_test_state;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::declare::declare_tx;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::invoke::{invoke_tx, InvokeTxArgs};
use crate::test_utils::{
    create_calldata, test_erc20_account_balance_key, test_erc20_sequencer_balance_key,
    CairoVersion, NonceManager, SaltManager, BALANCE, CHAIN_ID_NAME, CURRENT_BLOCK_NUMBER,
    CURRENT_BLOCK_TIMESTAMP, MAX_FEE, MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE,
    TEST_ACCOUNT_CONTRACT_ADDRESS, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH,
    TEST_CONTRACT_ADDRESS, TEST_EMPTY_CONTRACT_CAIRO0_PATH, TEST_EMPTY_CONTRACT_CAIRO1_PATH,
    TEST_EMPTY_CONTRACT_CLASS_HASH, TEST_ERC20_CONTRACT_ADDRESS, TEST_ERC20_CONTRACT_CLASS_HASH,
    TEST_SEQUENCER_ADDRESS,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants;
use crate::transaction::errors::{
    TransactionExecutionError, TransactionFeeError, TransactionPreValidationError,
};
use crate::transaction::objects::{
    AccountTransactionContext, FeeType, HasRelatedFeeType, ResourcesMapping,
    TransactionExecutionInfo,
};
use crate::transaction::test_utils::{
    account_invoke_tx, create_account_tx_for_validate_test, create_state_with_cairo1_account,
    create_state_with_trivial_validation_account, l1_resource_bounds, FaultyAccountTxCreatorArgs,
    CALL_CONTRACT, INVALID, VALID,
};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transactions::{
    DeployAccountTransaction, ExecutableTransaction, L1HandlerTransaction,
};
use crate::{
    check_entry_point_execution_error_for_custom_hint,
    check_transaction_execution_error_for_custom_hint,
    check_transaction_execution_error_for_invalid_scenario, declare_tx_args,
    deploy_account_tx_args, invoke_tx_args, retdata,
};

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
    fee_type: &FeeType,
    expected_fee_token_class_hash: ClassHash,
) -> Option<CallInfo> {
    let expected_sequencer_address = *block_context.sequencer_address.0.key();
    // The least significant 128 bits of the expected amount transferred.
    let lsb_expected_amount = stark_felt!(actual_fee.0);
    // The most significant 128 bits of the expected amount transferred.
    let msb_expected_amount = stark_felt!(0_u8);
    let storage_address = block_context.fee_token_address(fee_type);
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

    let sender_balance_key_low = get_fee_token_var_address(&account_address);
    let sender_balance_key_high =
        next_storage_key(&sender_balance_key_low).expect("Cannot get sender balance high key.");
    let sequencer_balance_key_low = get_fee_token_var_address(&block_context.sequencer_address);
    let sequencer_balance_key_high = next_storage_key(&sequencer_balance_key_low)
        .expect("Cannot get sequencer balance high key.");
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

/// Given the fee result of a single account transaction, verifies the final balances of the account
/// and the sequencer (in both fee types) are as expected (assuming the initial sequencer balances
/// are zero).
fn validate_final_balances(
    state: &mut CachedState<DictStateReader>,
    block_context: &BlockContext,
    expected_actual_fee: Fee,
    erc20_account_balance_key: StorageKey,
    fee_type: &FeeType,
    initial_account_balance_eth: u128,
    initial_account_balance_strk: u128,
) {
    // Expected balances of account and sequencer, per fee type.
    let (expected_sequencer_balance_eth, expected_sequencer_balance_strk) = match fee_type {
        FeeType::Eth => (stark_felt!(expected_actual_fee.0), StarkFelt::ZERO),
        FeeType::Strk => (StarkFelt::ZERO, stark_felt!(expected_actual_fee.0)),
    };
    let mut expected_account_balance_eth = initial_account_balance_eth;
    let mut expected_account_balance_strk = initial_account_balance_strk;
    if fee_type == &FeeType::Eth {
        expected_account_balance_eth -= expected_actual_fee.0;
    } else {
        expected_account_balance_strk -= expected_actual_fee.0;
    }

    // Verify balances of both accounts, of both fee types, are as expected.
    let eth_fee_token_address = block_context.fee_token_addresses.eth_fee_token_address;
    let strk_fee_token_address = block_context.fee_token_addresses.strk_fee_token_address;
    for (fee_address, expected_account_balance, expected_sequencer_balance) in [
        (eth_fee_token_address, expected_account_balance_eth, expected_sequencer_balance_eth),
        (strk_fee_token_address, expected_account_balance_strk, expected_sequencer_balance_strk),
    ] {
        let account_balance = state.get_storage_at(fee_address, erc20_account_balance_key).unwrap();
        assert_eq!(account_balance, stark_felt!(expected_account_balance));
        assert_eq!(
            state.get_storage_at(fee_address, test_erc20_sequencer_balance_key()).unwrap(),
            stark_felt!(expected_sequencer_balance)
        );
    }
}

fn default_invoke_tx_args(
    account_contract_address: ContractAddress,
    test_contract_address: ContractAddress,
) -> InvokeTxArgs {
    let execute_calldata = create_calldata(
        test_contract_address,
        "return_result",
        &[stark_felt!(2_u8)], // Calldata: num.
    );

    invoke_tx_args! {
        max_fee: Fee(MAX_FEE),
        signature: TransactionSignature::default(),
        nonce: Nonce::default(),
        sender_address: account_contract_address,
        calldata: execute_calldata,
    }
}

#[test_case(
    ExpectedResultTestInvokeTx{
        range_check: 102,
        n_steps: 4464,
        vm_resources: VmExecutionResources {
            n_steps:  62,
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
    ExpectedResultTestInvokeTx{
        range_check: 115,
        n_steps: 4917,
        vm_resources: VmExecutionResources {
            n_steps: 284,
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
    expected_arguments: ExpectedResultTestInvokeTx,
    account_cairo_version: CairoVersion,
) {
    let block_context = &BlockContext::create_for_account_testing();
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let state =
        &mut test_state(block_context, BALANCE, &[(account_contract, 1), (test_contract, 1)]);
    let test_contract_address = test_contract.get_instance_address(0);
    let account_contract_address = account_contract.get_instance_address(0);
    let invoke_tx =
        invoke_tx(default_invoke_tx_args(account_contract_address, test_contract_address));

    // Extract invoke transaction fields for testing, as it is consumed when creating an account
    // transaction.
    let calldata = Calldata(Arc::clone(&invoke_tx.calldata().0));
    let sender_address = invoke_tx.sender_address();

    let account_tx = AccountTransaction::Invoke(invoke_tx);
    let fee_type = &account_tx.fee_type();
    let actual_execution_info = account_tx.execute(state, block_context, true, true).unwrap();

    // Build expected validate call info.
    let expected_account_class_hash = account_contract.get_class_hash();
    let expected_validate_call_info = expected_validate_call_info(
        expected_account_class_hash,
        constants::VALIDATE_ENTRY_POINT_NAME,
        expected_arguments.validate_gas_consumed,
        calldata,
        sender_address,
        account_cairo_version,
    );

    // Build expected execute call info.
    let expected_return_result_calldata = vec![stark_felt!(2_u8)];
    let expected_return_result_call = CallEntryPoint {
        entry_point_selector: selector_from_name("return_result"),
        class_hash: Some(test_contract.get_class_hash()),
        code_address: Some(test_contract_address),
        entry_point_type: EntryPointType::External,
        calldata: Calldata(expected_return_result_calldata.clone().into()),
        storage_address: test_contract_address,
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
                n_steps: 23,
                n_memory_holes: 0,
                ..Default::default()
            },
            ..Default::default()
        }],
        ..Default::default()
    });

    // Build expected fee transfer call info.
    let expected_actual_fee =
        calculate_tx_fee(&actual_execution_info.actual_resources, block_context, fee_type).unwrap();
    let expected_fee_transfer_call_info = expected_fee_transfer_call_info(
        block_context,
        sender_address,
        expected_actual_fee,
        // TODO(Dori, 1/2/2024): The exact resources required in fee transfer depends non-trivially
        //   on the contract address (see `normalize_address` function in `storage.cairo`; the
        //   input is the address hashed with other arguments). Currently we differentiate between
        //   the expected results of the fee transfer call based on the account cairo version, but
        //   this is incorrect.
        VmExecutionResources {
            n_steps: match account_cairo_version {
                CairoVersion::Cairo0 => 529,
                CairoVersion::Cairo1 => 525,
            },
            n_memory_holes: match account_cairo_version {
                CairoVersion::Cairo0 => 57,
                CairoVersion::Cairo1 => 59,
            },
            builtin_instance_counter: HashMap::from([
                (HASH_BUILTIN_NAME.to_string(), 4),
                (RANGE_CHECK_BUILTIN_NAME.to_string(), 21),
            ]),
        },
        fee_type,
        FeatureContract::ERC20.get_class_hash(),
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
    validate_final_balances(
        state,
        block_context,
        expected_actual_fee,
        get_fee_token_var_address(&account_contract_address),
        fee_type,
        BALANCE,
        BALANCE,
    );
}

// Verifies the storage after each invoke execution in test_invoke_tx_advanced_operations.
fn verify_storage_after_invoke_advanced_operations(
    state: &mut CachedState<DictStateReader>,
    contract_address: ContractAddress,
    account_address: ContractAddress,
    index: StarkFelt,
    expected_counters: [StarkFelt; 2],
    expected_ec_point: [StarkFelt; 2],
    expected_nonce: Nonce,
) {
    // Verify the two_counters values in storage.
    let key = get_storage_var_address("two_counters", &[index]);
    let value = state.get_storage_at(contract_address, key).unwrap();
    assert_eq!(value, expected_counters[0]);
    let key = next_storage_key(&key).unwrap();
    let value = state.get_storage_at(contract_address, key).unwrap();
    assert_eq!(value, expected_counters[1]);

    // Verify the ec_point values in storage.
    let key = get_storage_var_address("ec_point", &[]);
    let value = state.get_storage_at(contract_address, key).unwrap();
    assert_eq!(value, expected_ec_point[0]);
    let key = next_storage_key(&key).unwrap();
    let value = state.get_storage_at(contract_address, key).unwrap();
    assert_eq!(value, expected_ec_point[1]);

    // Verify the nonce value in storage.
    let nonce_from_state = state.get_nonce_at(account_address).unwrap();
    assert_eq!(nonce_from_state, expected_nonce);
}

#[test]
fn test_invoke_tx_advanced_operations() {
    let cairo_version = CairoVersion::Cairo0;
    let block_context = &BlockContext::create_for_account_testing();
    let account = FeatureContract::AccountWithoutValidations(cairo_version);
    let test_contract = FeatureContract::TestContract(cairo_version);
    let state = &mut test_state(block_context, BALANCE, &[(account, 1), (test_contract, 1)]);
    let account_address = account.get_instance_address(0);
    let contract_address = test_contract.get_instance_address(0);
    let index = stark_felt!(123_u32);
    let base_tx_args = invoke_tx_args! {
        max_fee: Fee(MAX_FEE),
        sender_address: account_address,
    };

    // Invoke advance_counter function.
    let mut nonce_manager = NonceManager::default();
    let counter_diffs = [101_u32, 102_u32];
    let initial_counters = [stark_felt!(counter_diffs[0]), stark_felt!(counter_diffs[1])];
    let calldata_args = vec![index, initial_counters[0], initial_counters[1]];

    let account_tx = account_invoke_tx(invoke_tx_args! {
        nonce: nonce_manager.next(account_address),
        calldata:
            create_calldata(contract_address, "advance_counter", &calldata_args),
        ..base_tx_args.clone()
    });
    account_tx.execute(state, block_context, true, true).unwrap();

    let next_nonce = nonce_manager.next(account_address);
    let initial_ec_point = [StarkFelt::ZERO, StarkFelt::ZERO];
    verify_storage_after_invoke_advanced_operations(
        state,
        contract_address,
        account_address,
        index,
        initial_counters,
        initial_ec_point,
        next_nonce,
    );

    // Invoke call_xor_counters function.
    let xor_values = [31_u32, 32_u32];
    let calldata_args = vec![
        *contract_address.0.key(),
        index,
        stark_felt!(xor_values[0]),
        stark_felt!(xor_values[1]),
    ];

    let account_tx = account_invoke_tx(invoke_tx_args! {
        nonce: next_nonce,
        calldata:
            create_calldata(contract_address, "call_xor_counters", &calldata_args),
        ..base_tx_args.clone()
    });
    account_tx.execute(state, block_context, true, true).unwrap();

    let expected_counters = [
        stark_felt!(counter_diffs[0] ^ xor_values[0]),
        stark_felt!(counter_diffs[1] ^ xor_values[1]),
    ];
    let next_nonce = nonce_manager.next(account_address);
    verify_storage_after_invoke_advanced_operations(
        state,
        contract_address,
        account_address,
        index,
        expected_counters,
        initial_ec_point,
        next_nonce,
    );

    // Invoke test_ec_op function.
    let account_tx = account_invoke_tx(invoke_tx_args! {
        nonce: next_nonce,
        calldata:
            create_calldata(contract_address, "test_ec_op", &[]),
        ..base_tx_args.clone()
    });
    account_tx.execute(state, block_context, true, true).unwrap();

    let expected_ec_point = [
        StarkFelt::new([
            0x05, 0x07, 0xF8, 0x28, 0xEA, 0xE0, 0x0C, 0x08, 0xED, 0x10, 0x60, 0x5B, 0xAA, 0xD4,
            0x80, 0xB7, 0x4B, 0x0E, 0x9B, 0x61, 0x9C, 0x1A, 0x2C, 0x53, 0xFB, 0x75, 0x86, 0xE3,
            0xEE, 0x1A, 0x82, 0xBA,
        ])
        .unwrap(),
        StarkFelt::new([
            0x05, 0x43, 0x9A, 0x5D, 0xC0, 0x8C, 0xC1, 0x35, 0x64, 0x11, 0xA4, 0x57, 0x8F, 0x50,
            0x71, 0x54, 0xB4, 0x84, 0x7B, 0xAA, 0x73, 0x70, 0x68, 0x17, 0x1D, 0xFA, 0x6C, 0x8A,
            0xB3, 0x49, 0x9D, 0x8B,
        ])
        .unwrap(),
    ];
    let next_nonce = nonce_manager.next(account_address);
    verify_storage_after_invoke_advanced_operations(
        state,
        contract_address,
        account_address,
        index,
        expected_counters,
        expected_ec_point,
        next_nonce,
    );

    // Invoke add_signature_to_counters function.
    let signature_values = [Felt252::from(200_u64), Felt252::from(300_u64)];
    let signature = TransactionSignature(signature_values.iter().map(felt_to_stark_felt).collect());

    let account_tx = account_invoke_tx(invoke_tx_args! {
        signature,
        nonce: next_nonce,
        calldata:
            create_calldata(contract_address, "add_signature_to_counters", &[index]),
        ..base_tx_args.clone()
    });
    account_tx.execute(state, block_context, true, true).unwrap();

    let expected_counters = [
        felt_to_stark_felt(
            &(stark_felt_to_felt(expected_counters[0]) + signature_values[0].clone()),
        ),
        felt_to_stark_felt(
            &(stark_felt_to_felt(expected_counters[1]) + signature_values[1].clone()),
        ),
    ];
    let next_nonce = nonce_manager.next(account_address);
    verify_storage_after_invoke_advanced_operations(
        state,
        contract_address,
        account_address,
        index,
        expected_counters,
        expected_ec_point,
        next_nonce,
    );

    // Invoke send_message function that send a message to L1.
    let to_address = Felt252::from(85);
    let account_tx = account_invoke_tx(invoke_tx_args! {
        nonce: next_nonce,
        calldata:
            create_calldata(contract_address, "send_message", &[felt_to_stark_felt(&to_address)]),
        ..base_tx_args
    });
    let execution_info = account_tx.execute(state, block_context, true, true).unwrap();
    let next_nonce = nonce_manager.next(account_address);
    verify_storage_after_invoke_advanced_operations(
        state,
        contract_address,
        account_address,
        index,
        expected_counters,
        expected_ec_point,
        next_nonce,
    );
    let expected_msg = OrderedL2ToL1Message {
        order: 0,
        message: MessageToL1 {
            to_address: EthAddress::try_from(felt_to_stark_felt(&to_address)).unwrap(),
            payload: L2ToL1Payload(vec![stark_felt!(12_u32), stark_felt!(34_u32)]),
        },
    };
    assert_eq!(
        expected_msg,
        execution_info.execute_call_info.unwrap().inner_calls[0].execution.l2_to_l1_messages[0]
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
    let execute_calldata = create_calldata(
        contract_address!(TEST_ERC20_CONTRACT_ADDRESS),
        "permissionedMint",
        &[recipient, mint_low, mint_high],
    );
    let account_tx = account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(MAX_FEE),
        sender_address: contract_address!(TEST_ACCOUNT_CONTRACT_ADDRESS),
        calldata: execute_calldata,
        version: TransactionVersion::ONE,
        nonce: Nonce::default(),
    });
    let fee_token_address = block_context.fee_token_address(&account_tx.fee_type());
    account_tx.execute(state, block_context, true, true).unwrap();

    // Get balance from state, and validate.
    let (low, high) =
        state.get_fee_token_balance(&contract_address!(recipient), &fee_token_address).unwrap();

    assert_eq!(low, mint_low);
    assert_eq!(high, mint_high);
}

fn assert_failure_if_resource_bounds_exceed_balance(
    state: &mut CachedState<DictStateReader>,
    block_context: &BlockContext,
    invalid_tx: AccountTransaction,
) {
    match invalid_tx.get_account_tx_context() {
        AccountTransactionContext::Deprecated(context) => {
            assert_matches!(
                invalid_tx.execute(state, block_context, true, true).unwrap_err(),
                TransactionExecutionError::TransactionPreValidationError(
                    TransactionPreValidationError::TransactionFeeError(
                        TransactionFeeError::MaxFeeExceedsBalance{ max_fee, .. }))
                if max_fee == context.max_fee
            );
        }
        AccountTransactionContext::Current(context) => {
            let l1_bounds = context.l1_resource_bounds().unwrap();
            assert_matches!(
                invalid_tx.execute(state, block_context, true, true).unwrap_err(),
                TransactionExecutionError::TransactionPreValidationError(
                    TransactionPreValidationError::TransactionFeeError(
                        TransactionFeeError::L1GasBoundsExceedBalance{ max_amount, max_price, .. }))
                if max_amount == l1_bounds.max_amount && max_price == l1_bounds.max_price_per_unit
            );
        }
    };
}

#[test_case(CairoVersion::Cairo0; "With Cairo0 account")]
#[test_case(CairoVersion::Cairo1; "With Cairo1 account")]
fn test_max_fee_exceeds_balance(account_cairo_version: CairoVersion) {
    let block_context = &BlockContext::create_for_account_testing();
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let state =
        &mut test_state(block_context, BALANCE, &[(account_contract, 1), (test_contract, 1)]);
    let account_contract_address = account_contract.get_instance_address(0);
    let default_args =
        default_invoke_tx_args(account_contract_address, test_contract.get_instance_address(0));

    let invalid_max_fee = Fee(BALANCE + 1);
    let invalid_resource_bounds =
        l1_resource_bounds((BALANCE / MAX_L1_GAS_PRICE) as u64 + 1, MAX_L1_GAS_PRICE);

    // V1 Invoke.
    let invalid_tx = account_invoke_tx(invoke_tx_args! {
        max_fee: invalid_max_fee,
        version: TransactionVersion::ONE,
        ..default_args.clone()
    });
    assert_failure_if_resource_bounds_exceed_balance(state, block_context, invalid_tx);

    // V3 invoke.
    let invalid_tx = account_invoke_tx(invoke_tx_args! {
        resource_bounds: invalid_resource_bounds,
        version: TransactionVersion::THREE,
        ..default_args
    });
    assert_failure_if_resource_bounds_exceed_balance(state, block_context, invalid_tx);

    // Deploy.
    let invalid_tx = AccountTransaction::DeployAccount(deploy_account_tx(
        format!("{}", test_contract.get_class_hash().0).as_str(),
        None,
        None,
        &mut NonceManager::default(),
    ));
    assert_failure_if_resource_bounds_exceed_balance(state, block_context, invalid_tx);

    // Declare.
    let contract_to_declare = FeatureContract::Empty(CairoVersion::Cairo0);
    let invalid_tx = declare_tx(
        declare_tx_args! {
            class_hash: contract_to_declare.get_class_hash(),
            sender_address: account_contract_address,
            max_fee: invalid_max_fee,
        },
        contract_to_declare.get_class(),
    );
    assert_failure_if_resource_bounds_exceed_balance(state, block_context, invalid_tx);
}

#[test_case(CairoVersion::Cairo0; "With Cairo0 account")]
#[test_case(CairoVersion::Cairo1; "With Cairo1 account")]
fn test_insufficient_resource_bounds(account_cairo_version: CairoVersion) {
    let block_context = &BlockContext::create_for_account_testing();
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let state =
        &mut test_state(block_context, BALANCE, &[(account_contract, 1), (test_contract, 1)]);
    let valid_invoke_tx_args = default_invoke_tx_args(
        account_contract.get_instance_address(0),
        test_contract.get_instance_address(0),
    );

    // The minimal gas estimate does not depend on tx version.
    let minimal_l1_gas =
        estimate_minimal_l1_gas(block_context, &account_invoke_tx(valid_invoke_tx_args.clone()))
            .unwrap();

    // Test V1 transaction.

    let minimal_fee = Fee(minimal_l1_gas * block_context.gas_prices.eth_l1_gas_price);
    // Max fee too low (lower than minimal estimated fee).
    let invalid_max_fee = Fee(minimal_fee.0 - 1);
    let invalid_v1_tx = account_invoke_tx(
        invoke_tx_args! { max_fee: invalid_max_fee, ..valid_invoke_tx_args.clone() },
    );
    let execution_error = invalid_v1_tx.execute(state, block_context, true, true).unwrap_err();

    // Test error.
    assert_matches!(
        execution_error,
        TransactionExecutionError::TransactionPreValidationError(
            TransactionPreValidationError::TransactionFeeError(
                TransactionFeeError::MaxFeeTooLow { min_fee, max_fee }))
        if max_fee == invalid_max_fee && min_fee == minimal_fee
    );

    // Test V3 transaction.
    let actual_strk_l1_gas_price = block_context.gas_prices.strk_l1_gas_price;

    // Max L1 gas amount too low.
    let insufficient_max_l1_gas_amount = (minimal_l1_gas - 1) as u64;
    let invalid_v3_tx = account_invoke_tx(invoke_tx_args! {
        resource_bounds: l1_resource_bounds(insufficient_max_l1_gas_amount, actual_strk_l1_gas_price),
        version: TransactionVersion::THREE,
        ..valid_invoke_tx_args.clone()
    });
    let execution_error = invalid_v3_tx.execute(state, block_context, true, true).unwrap_err();
    assert_matches!(
        execution_error,
        TransactionExecutionError::TransactionPreValidationError(
            TransactionPreValidationError::TransactionFeeError(
                TransactionFeeError::MaxL1GasAmountTooLow{
                    max_l1_gas_amount, minimal_l1_gas_amount }))
        if max_l1_gas_amount == insufficient_max_l1_gas_amount &&
        minimal_l1_gas_amount == minimal_l1_gas as u64
    );

    // Max L1 gas price too low.
    let insufficient_max_l1_gas_price = actual_strk_l1_gas_price - 1;
    let invalid_v3_tx = account_invoke_tx(invoke_tx_args! {
        resource_bounds: l1_resource_bounds(minimal_l1_gas as u64, insufficient_max_l1_gas_price),
        version: TransactionVersion::THREE,
        ..valid_invoke_tx_args
    });
    let execution_error = invalid_v3_tx.execute(state, block_context, true, true).unwrap_err();
    assert_matches!(
        execution_error,
        TransactionExecutionError::TransactionPreValidationError(
            TransactionPreValidationError::TransactionFeeError(
                TransactionFeeError::MaxL1GasPriceTooLow{ max_l1_gas_price, actual_l1_gas_price }))
        if max_l1_gas_price == insufficient_max_l1_gas_price &&
        actual_l1_gas_price == actual_strk_l1_gas_price
    );
}

#[test_case(CairoVersion::Cairo0; "With Cairo0 account")]
#[test_case(CairoVersion::Cairo1; "With Cairo1 account")]
fn test_actual_fee_gt_resource_bounds(account_cairo_version: CairoVersion) {
    let block_context = &BlockContext::create_for_account_testing();
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let state =
        &mut test_state(block_context, BALANCE, &[(account_contract, 1), (test_contract, 1)]);
    let invoke_tx_args = default_invoke_tx_args(
        account_contract.get_instance_address(0),
        test_contract.get_instance_address(0),
    );

    let minimal_l1_gas =
        estimate_minimal_l1_gas(block_context, &account_invoke_tx(invoke_tx_args.clone())).unwrap();
    let minimal_fee = Fee(minimal_l1_gas * block_context.gas_prices.eth_l1_gas_price);
    // The estimated minimal fee is lower than the actual fee.
    let invalid_tx = account_invoke_tx(invoke_tx_args! { max_fee: minimal_fee, ..invoke_tx_args });

    let execution_result = invalid_tx.execute(state, block_context, true, true).unwrap();
    let execution_error = execution_result.revert_error.unwrap();
    // Test error.
    assert!(execution_error.starts_with("Insufficient max fee:"));
    // Test that fee was charged.
    assert_eq!(execution_result.actual_fee, minimal_fee);
}

#[test_case(CairoVersion::Cairo0; "With Cairo0 account")]
#[test_case(CairoVersion::Cairo1; "With Cairo1 account")]
fn test_invalid_nonce(account_cairo_version: CairoVersion) {
    let block_context = &BlockContext::create_for_account_testing();
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let state =
        &mut test_state(block_context, BALANCE, &[(account_contract, 1), (test_contract, 1)]);
    let valid_invoke_tx_args = default_invoke_tx_args(
        account_contract.get_instance_address(0),
        test_contract.get_instance_address(0),
    );
    let mut transactional_state = CachedState::create_transactional(state);

    // Strict, negative flow: account nonce = 0, incoming tx nonce = 1.
    let invalid_nonce = Nonce(stark_felt!(1_u8));
    let invalid_tx =
        account_invoke_tx(invoke_tx_args! { nonce: invalid_nonce, ..valid_invoke_tx_args.clone() });
    let invalid_tx_context = invalid_tx.get_account_tx_context();
    let pre_validation_err = invalid_tx
        .perform_pre_validation_stage(
            &mut transactional_state,
            &invalid_tx_context,
            block_context,
            false,
            true,
        )
        .unwrap_err();

    // Test error.
    assert_matches!(
        pre_validation_err,
            TransactionPreValidationError::InvalidNonce {address, account_nonce, incoming_tx_nonce}
        if (address, account_nonce, incoming_tx_nonce) ==
        (valid_invoke_tx_args.sender_address, Nonce::default(), invalid_nonce)
    );

    // Non-strict.

    // Positive flow: account nonce = 0, incoming tx nonce = 1.
    let valid_nonce = Nonce(stark_felt!(1_u8));
    let valid_tx =
        account_invoke_tx(invoke_tx_args! { nonce: valid_nonce, ..valid_invoke_tx_args.clone() });
    let valid_tx_context = valid_tx.get_account_tx_context();
    valid_tx
        .perform_pre_validation_stage(
            &mut transactional_state,
            &valid_tx_context,
            block_context,
            false,
            false,
        )
        .unwrap();

    // Negative flow: account nonce = 1, incoming tx nonce = 0.
    let invalid_nonce = Nonce(stark_felt!(0_u8));
    let invalid_tx =
        account_invoke_tx(invoke_tx_args! { nonce: invalid_nonce, ..valid_invoke_tx_args.clone() });
    let pre_validation_err = invalid_tx
        .perform_pre_validation_stage(
            &mut transactional_state,
            &invalid_tx.get_account_tx_context(),
            block_context,
            false,
            false,
        )
        .unwrap_err();

    // Test error.
    assert_matches!(
        pre_validation_err,
        TransactionPreValidationError::InvalidNonce {address, account_nonce, incoming_tx_nonce}
        if (address, account_nonce, incoming_tx_nonce) ==
        (valid_invoke_tx_args.sender_address, Nonce(stark_felt!(1_u8)), invalid_nonce)
    );
}

/// Returns the expected number of range checks in a declare transaction.
fn declare_expected_range_check_builtin(
    version: TransactionVersion,
    declared_contract_version: CairoVersion,
) -> usize {
    // Cairo1 account has a vector as input in `__validate__`, so extra range checks needed.
    // Not relevant in v0 transactions (no validate).
    if version > TransactionVersion::ZERO
        && matches!(declared_contract_version, CairoVersion::Cairo1)
    {
        65
    } else {
        63
    }
}

/// Returns the expected number of cairo steps in a declare transaction.
fn declare_n_steps(version: TransactionVersion, declared_contract_version: CairoVersion) -> usize {
    if version == TransactionVersion::ZERO {
        2909 // No `__validate__`. Same number of steps, regardless of declared contract version.
    } else {
        match declared_contract_version {
            CairoVersion::Cairo0 => 2921,
            CairoVersion::Cairo1 => 2959,
        }
    }
}

/// Expected CallInfo for `__validate__` call in a declare transaction.
fn declare_validate_callinfo(
    version: TransactionVersion,
    declared_contract_version: CairoVersion,
    declared_class_hash: ClassHash,
    account_class_hash: ClassHash,
    account_address: ContractAddress,
) -> Option<CallInfo> {
    // V0 transactions do not run validate.
    if version == TransactionVersion::ZERO {
        None
    } else {
        expected_validate_call_info(
            account_class_hash,
            constants::VALIDATE_DECLARE_ENTRY_POINT_NAME,
            0,
            calldata![declared_class_hash.0],
            account_address,
            declared_contract_version,
        )
    }
}

/// Expected amount of memory words changed during execution of a declare transaction.
fn declare_expected_memory_words(version: TransactionVersion) -> usize {
    2 * match version {
        TransactionVersion::ZERO => 1, // 1 storage update (sender balance), no nonce change.
        TransactionVersion::ONE => 2,  // 1 modified contract (nonce), 1 sender balance update.
        TransactionVersion::TWO | TransactionVersion::THREE => 3, // Also set compiled class hash.
        version => panic!("Unsupported version {version:?}."),
    }
}

#[rstest]
#[case(&mut create_state_with_trivial_validation_account(), CairoVersion::Cairo0)]
#[case(&mut create_state_with_cairo1_account(), CairoVersion::Cairo1)]
fn test_declare_tx(
    #[case] state: &mut CachedState<DictStateReader>,
    #[case] cairo_version: CairoVersion,
    #[values(
        TransactionVersion::ZERO,
        TransactionVersion::ONE,
        TransactionVersion::TWO,
        TransactionVersion::THREE
    )]
    version: TransactionVersion,
) {
    let block_context = &BlockContext::create_for_account_testing();
    let class_hash = class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH);
    let sender_address = contract_address!(TEST_ACCOUNT_CONTRACT_ADDRESS);
    let contract_class = if version < TransactionVersion::TWO {
        ContractClass::V0(ContractClassV0::from_file(TEST_EMPTY_CONTRACT_CAIRO0_PATH))
    } else {
        ContractClass::V1(ContractClassV1::from_file(TEST_EMPTY_CONTRACT_CAIRO1_PATH))
    };

    let account_tx = declare_tx(
        declare_tx_args! {
            max_fee: Fee(MAX_FEE),
            sender_address,
            version,
            resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
            class_hash,
        },
        contract_class.clone(),
    );

    // Check state before transaction application.
    assert_matches!(
        state.get_compiled_contract_class(&class_hash).unwrap_err(),
        StateError::UndeclaredClassHash(undeclared_class_hash) if
        undeclared_class_hash == class_hash
    );
    let fee_type = &account_tx.fee_type();
    let actual_execution_info = account_tx.execute(state, block_context, true, true).unwrap();

    // Build expected validate call info.
    let expected_account_address = contract_address!(TEST_ACCOUNT_CONTRACT_ADDRESS);
    let expected_validate_call_info = declare_validate_callinfo(
        version,
        cairo_version,
        class_hash,
        class_hash!(TEST_ACCOUNT_CONTRACT_CLASS_HASH),
        expected_account_address,
    );

    // Build expected fee transfer call info.
    let expected_actual_fee =
        calculate_tx_fee(&actual_execution_info.actual_resources, block_context, fee_type).unwrap();
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
        fee_type,
        class_hash!(TEST_ERC20_CONTRACT_CLASS_HASH),
    );

    let expected_execution_info = TransactionExecutionInfo {
        validate_call_info: expected_validate_call_info,
        execute_call_info: None,
        fee_transfer_call_info: expected_fee_transfer_call_info,
        actual_fee: expected_actual_fee,
        revert_error: None,
        actual_resources: ResourcesMapping(HashMap::from([
            (
                abi_constants::GAS_USAGE.to_string(),
                declare_expected_memory_words(version)
                    * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD,
            ),
            (HASH_BUILTIN_NAME.to_string(), 15),
            (
                RANGE_CHECK_BUILTIN_NAME.to_string(),
                declare_expected_range_check_builtin(version, cairo_version),
            ),
            (abi_constants::N_STEPS_RESOURCE.to_string(), declare_n_steps(version, cairo_version)),
        ])),
    };

    // Test execution info result.
    assert_eq!(actual_execution_info, expected_execution_info);

    // Test nonce update. V0 transactions do not update nonce.
    let expected_nonce =
        Nonce(stark_felt!(if version == TransactionVersion::ZERO { 0_u8 } else { 1_u8 }));
    let nonce_from_state = state.get_nonce_at(sender_address).unwrap();
    assert_eq!(nonce_from_state, expected_nonce);

    // Test final balances.
    validate_final_balances(
        state,
        block_context,
        expected_actual_fee,
        test_erc20_account_balance_key(),
        fee_type,
        BALANCE,
        BALANCE,
    );

    // Verify class declaration.
    let contract_class_from_state = state.get_compiled_contract_class(&class_hash).unwrap();
    assert_eq!(contract_class_from_state, contract_class);
}

// TODO(Dori, 1/1/2024): Input account class hash should be of type `ClassHash`.
fn deploy_account_tx(
    account_class_hash: &str,
    constructor_calldata: Option<Calldata>,
    signature: Option<TransactionSignature>,
    nonce_manager: &mut NonceManager,
) -> DeployAccountTransaction {
    crate::test_utils::deploy_account::deploy_account_tx(
        deploy_account_tx_args! {
            class_hash: class_hash!(account_class_hash),
            max_fee: Fee(MAX_FEE),
            constructor_calldata: constructor_calldata.unwrap_or_default(),
            signature: signature.unwrap_or_default(),
        },
        nonce_manager,
    )
}

#[test_case(
    &mut create_state_with_trivial_validation_account(),
    83, // range_check_builtin
    3893, // n_steps
    CairoVersion::Cairo0;
    "With Cairo0 account")]
#[test_case(
    &mut create_state_with_cairo1_account(),
    85, // range_check_builtin
    3949, // n_steps
    CairoVersion::Cairo1;
    "With Cairo1 account")]
fn test_deploy_account_tx(
    state: &mut CachedState<DictStateReader>,
    expected_range_check_builtin: usize,
    expected_n_steps_resource: usize,
    cairo_version: CairoVersion,
) {
    let block_context = &BlockContext::create_for_account_testing();
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
    let deployed_account_balance_key = get_fee_token_var_address(&deployed_account_address);
    for fee_type in FeeType::iter() {
        state.set_storage_at(
            block_context.fee_token_address(&fee_type),
            deployed_account_balance_key,
            stark_felt!(BALANCE),
        );
    }

    let account_tx = AccountTransaction::DeployAccount(deploy_account);
    let fee_type = &account_tx.fee_type();
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
        calculate_tx_fee(&actual_execution_info.actual_resources, block_context, fee_type).unwrap();
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
        fee_type,
        class_hash!(TEST_ERC20_CONTRACT_CLASS_HASH),
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
    validate_final_balances(
        state,
        block_context,
        expected_actual_fee,
        deployed_account_balance_key,
        fee_type,
        BALANCE,
        BALANCE,
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

#[rstest]
fn test_fail_deploy_account_undeclared_class_hash() {
    let mut state = create_state_with_trivial_validation_account();
    let block_context = &BlockContext::create_for_account_testing();
    let mut nonce_manager = NonceManager::default();
    let undeclared_hash = "0xdeadbeef";
    let deploy_account = deploy_account_tx(undeclared_hash, None, None, &mut nonce_manager);

    // Fund account, so as not to fail pre-validation.
    state.set_storage_at(
        block_context.fee_token_address(&FeeType::Eth),
        get_fee_token_var_address(&deploy_account.contract_address),
        stark_felt!(BALANCE),
    );

    let account_tx = AccountTransaction::DeployAccount(deploy_account);
    let error = account_tx.execute(&mut state, block_context, true, true).unwrap_err();
    assert_matches!(
        error,
        TransactionExecutionError::ContractConstructorExecutionFailed(
            EntryPointExecutionError::StateError(StateError::UndeclaredClassHash(class_hash))
        )
        if class_hash == class_hash!(undeclared_hash)
    );
}

// TODO(Arni, 1/1/2024): Consider converting this test to use V3 txs.
#[rstest]
fn test_validate_accounts_tx(
    #[values(
        TransactionType::InvokeFunction,
        TransactionType::Declare,
        TransactionType::DeployAccount
    )]
    tx_type: TransactionType,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let block_context = &BlockContext::create_for_account_testing();
    let account_balance = 0;
    let faulty_account = FeatureContract::FaultyAccount(cairo_version);
    let sender_address = faulty_account.get_instance_address(0);
    let state = &mut test_state(block_context, account_balance, &[(faulty_account, 1)]);
    let salt_manager = &mut SaltManager::default();

    // Negative flows.

    // Logic failure.
    let account_tx = create_account_tx_for_validate_test(
        FaultyAccountTxCreatorArgs {
            tx_type,
            scenario: INVALID,
            additional_data: None,
            faulty_account,
            sender_address,
            contract_address_salt: salt_manager.next_salt(),
            max_fee: None,
        },
        &mut NonceManager::default(),
    );
    let error = account_tx.execute(state, block_context, true, true).unwrap_err();
    check_transaction_execution_error_for_invalid_scenario!(cairo_version, error);

    // Trying to call another contract (forbidden).
    let account_tx = create_account_tx_for_validate_test(
        FaultyAccountTxCreatorArgs {
            tx_type,
            scenario: CALL_CONTRACT,
            additional_data: Some(stark_felt!("0x1991")), /* Some address different than the
                                                           * address of faulty_account. */
            faulty_account,
            sender_address,
            contract_address_salt: salt_manager.next_salt(),
            max_fee: None,
        },
        &mut NonceManager::default(),
    );
    let error = account_tx.execute(state, block_context, true, true).unwrap_err();
    check_transaction_execution_error_for_custom_hint!(
        &error,
        "Unauthorized syscall call_contract in execution mode Validate.",
        ValidateTransactionError,
    );

    // Verify that the contract does not call another contract in the constructor of deploy account
    // as well.
    if tx_type == TransactionType::DeployAccount {
        // Deploy another instance of 'faulty_account' and trying to call other contract in the
        // constructor (forbidden).
        let deploy_account_tx = crate::test_utils::deploy_account::deploy_account_tx(
            deploy_account_tx_args! {
                class_hash: faulty_account.get_class_hash(),
                constructor_calldata: calldata![stark_felt!(constants::FELT_TRUE)],
                // Run faulty_validate() in the constructor.
                signature: TransactionSignature(vec![
                    stark_felt!(CALL_CONTRACT),
                    *sender_address.0.key(),
                ]),
                contract_address_salt: salt_manager.next_salt(),
            },
            &mut NonceManager::default(),
        );
        let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);
        let error = account_tx.execute(state, block_context, true, true).unwrap_err();
        check_transaction_execution_error_for_custom_hint!(
            &error,
            "Unauthorized syscall call_contract in execution mode Validate.",
            ContractConstructorExecutionFailed,
        );
    }

    // Positive flows.

    // Valid logic.
    let nonce_manager = &mut NonceManager::default();
    let account_tx = create_account_tx_for_validate_test(
        FaultyAccountTxCreatorArgs {
            tx_type,
            scenario: VALID,
            additional_data: None,
            faulty_account,
            sender_address,
            contract_address_salt: salt_manager.next_salt(),
            max_fee: None,
        },
        nonce_manager,
    );
    account_tx.execute(state, block_context, true, true).unwrap();

    if tx_type != TransactionType::DeployAccount {
        // Calling self (allowed).
        let account_tx = create_account_tx_for_validate_test(
            FaultyAccountTxCreatorArgs {
                tx_type,
                scenario: CALL_CONTRACT,
                additional_data: Some(*sender_address.0.key()),
                faulty_account,
                sender_address,
                contract_address_salt: ContractAddressSalt::default(),
                max_fee: None,
            },
            nonce_manager,
        );
        account_tx.execute(state, block_context, true, true).unwrap();
    }
}

// Test that we exclude the fee token contract modification and adds the account’s balance change
// in the state changes.
#[test]
fn test_calculate_tx_gas_usage() {
    let account_cairo_version = CairoVersion::Cairo0;
    let test_contract_cairo_version = CairoVersion::Cairo0;
    let block_context = &BlockContext::create_for_account_testing();
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(test_contract_cairo_version);
    let account_contract_address = account_contract.get_instance_address(0);
    let state =
        &mut test_state(block_context, BALANCE, &[(account_contract, 1), (test_contract, 1)]);

    let account_tx = account_invoke_tx(default_invoke_tx_args(
        account_contract_address,
        test_contract.get_instance_address(0),
    ));
    let fee_token_address = block_context.fee_token_address(&account_tx.fee_type());
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

    assert_eq!(tx_execution_info.actual_resources.gas_usage(), l1_gas_usage);

    // A tx that changes the account and some other balance in execute.
    let some_other_account_address = account_contract.get_instance_address(17);
    let execute_calldata = create_calldata(
        fee_token_address,
        constants::TRANSFER_ENTRY_POINT_NAME,
        &[
            *some_other_account_address.0.key(), // Calldata: recipient.
            stark_felt!(2_u8),                   // Calldata: lsb amount.
            stark_felt!(0_u8),                   // Calldata: msb amount.
        ],
    );

    let account_tx = account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(MAX_FEE),
        sender_address: account_contract_address,
        calldata: execute_calldata,
        version: TransactionVersion::ONE,
        nonce: Nonce(stark_felt!(1_u8)),
    });

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

    assert_eq!(tx_execution_info.actual_resources.gas_usage(), l1_gas_usage);
}

#[rstest]
fn test_valid_flag(
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] account_cairo_version: CairoVersion,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] test_contract_cairo_version: CairoVersion,
) {
    let block_context = &BlockContext::create_for_account_testing();
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(test_contract_cairo_version);
    let state =
        &mut test_state(block_context, BALANCE, &[(account_contract, 1), (test_contract, 1)]);

    let account_tx = account_invoke_tx(default_invoke_tx_args(
        account_contract.get_instance_address(0),
        test_contract.get_instance_address(0),
    ));

    let actual_execution_info = account_tx.execute(state, block_context, true, false).unwrap();

    assert!(actual_execution_info.validate_call_info.is_none());
}

// TODO(Noa,01/12/2023): Consider moving it to syscall_test.
#[rstest]
#[case(true)]
#[case(false)]
fn test_only_query_flag(#[case] only_query: bool) {
    let account_balance = BALANCE;
    let block_context = &BlockContext::create_for_account_testing();
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let state =
        &mut test_state(block_context, account_balance, &[(account, 1), (test_contract, 1)]);
    let mut version = Felt252::from(1_u8);
    if only_query {
        let query_version_base = Pow::pow(Felt252::from(2_u8), constants::QUERY_VERSION_BASE_BIT);
        version += query_version_base;
    }
    let sender_address = account.get_instance_address(0);
    let test_contract_address = test_contract.get_instance_address(0);
    let max_fee = Fee(MAX_FEE);
    let expected_tx_info = vec![
        felt_to_stark_felt(&version), // Transaction version.
        *sender_address.0.key(),      // Account address.
        stark_felt!(max_fee.0),       // Max fee.
        StarkFelt::ZERO,              // Signature.
        StarkFelt::ZERO,              // Transaction hash.
        stark_felt!(&*ChainId(CHAIN_ID_NAME.to_string()).as_hex()), // Chain ID.
        StarkFelt::ZERO,              // Nonce.
        StarkFelt::ZERO,              // Length of resource bounds array.
        StarkFelt::ZERO,              // Tip.
        StarkFelt::ZERO,              // Paymaster data.
        StarkFelt::ZERO,              // Nonce DA.
        StarkFelt::ZERO,              // Fee DA.
        StarkFelt::ZERO,              // Account data.
    ];
    let entry_point_selector = selector_from_name("test_get_execution_info");
    let expected_call_info = vec![
        *sender_address.0.key(),             // Caller address.
        *test_contract_address.0.key(),      // Storage address.
        stark_felt!(entry_point_selector.0), // Entry point selector.
    ];
    let expected_block_info = [
        stark_felt!(CURRENT_BLOCK_NUMBER),    // Block number.
        stark_felt!(CURRENT_BLOCK_TIMESTAMP), // Block timestamp.
        stark_felt!(TEST_SEQUENCER_ADDRESS),  // Sequencer address.
    ];
    let calldata_len =
        expected_block_info.len() + expected_tx_info.len() + expected_call_info.len();
    let execute_calldata = vec![
        *test_contract_address.0.key(),   // Contract address.
        entry_point_selector.0,           // EP selector.
        stark_felt!(calldata_len as u64), // Calldata length.
    ];
    let execute_calldata = Calldata(
        [
            execute_calldata,
            expected_block_info.clone().to_vec(),
            expected_tx_info.clone(),
            expected_call_info,
        ]
        .concat()
        .into(),
    );
    let invoke_tx = crate::test_utils::invoke::invoke_tx(
        invoke_tx_args! { calldata: execute_calldata, max_fee, sender_address, only_query },
    );
    let account_tx = AccountTransaction::Invoke(invoke_tx);

    let tx_execution_info = account_tx.execute(state, block_context, true, true).unwrap();
    assert!(!tx_execution_info.is_reverted())
}

fn l1_handler_tx(calldata: &Calldata, l1_fee: Fee) -> L1HandlerTransaction {
    L1HandlerTransaction {
        tx: starknet_api::transaction::L1HandlerTransaction {
            version: TransactionVersion::ZERO,
            nonce: Nonce::default(),
            contract_address: contract_address!(TEST_CONTRACT_ADDRESS),
            entry_point_selector: selector_from_name("l1_handler_set_value"),
            calldata: calldata.clone(),
        },
        tx_hash: TransactionHash::default(),
        paid_fee_on_l1: l1_fee,
    }
}

#[test]
fn test_l1_handler() {
    let state = &mut create_test_state();
    let block_context = &BlockContext::create_for_account_testing();
    let from_address = StarkFelt::from_u128(0x123);
    let key = StarkFelt::from_u128(0x876);
    let value = StarkFelt::from_u128(0x44);
    let calldata = calldata![from_address, key, value];
    let tx = l1_handler_tx(&calldata, Fee(1));

    let actual_execution_info = tx.execute(state, block_context, true, true).unwrap();

    // Build the expected call info.
    let accessed_storage_key = StorageKey::try_from(key).unwrap();
    let expected_call_info = CallInfo {
        call: CallEntryPoint {
            class_hash: Some(class_hash!(TEST_CLASS_HASH)),
            code_address: None,
            entry_point_type: EntryPointType::L1Handler,
            entry_point_selector: selector_from_name("l1_handler_set_value"),
            calldata: calldata.clone(),
            storage_address: contract_address!(TEST_CONTRACT_ADDRESS),
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
            initial_gas: Transaction::initial_gas(),
        },
        execution: CallExecution {
            retdata: Retdata(vec![value]),
            gas_consumed: 19650,
            ..Default::default()
        },
        vm_resources: VmExecutionResources {
            n_steps: 143,
            n_memory_holes: 1,
            builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 5)]),
        },
        accessed_storage_keys: HashSet::from_iter(vec![accessed_storage_key]),
        ..Default::default()
    };

    // Build the expected resource mapping.
    let expected_resource_mapping = ResourcesMapping(HashMap::from([
        (HASH_BUILTIN_NAME.to_string(), 11),
        (abi_constants::N_STEPS_RESOURCE.to_string(), 1390),
        (RANGE_CHECK_BUILTIN_NAME.to_string(), 23),
        (abi_constants::GAS_USAGE.to_string(), 18471),
    ]));

    // Build the expected execution info.
    let expected_execution_info = TransactionExecutionInfo {
        validate_call_info: None,
        execute_call_info: Some(expected_call_info),
        fee_transfer_call_info: None,
        actual_fee: Fee(0),
        actual_resources: expected_resource_mapping,
        revert_error: None,
    };

    // Check the actual returned execution info.
    assert_eq!(actual_execution_info, expected_execution_info);

    // Check the state changes.
    assert_eq!(
        state
            .get_storage_at(
                contract_address!(TEST_CONTRACT_ADDRESS),
                StorageKey::try_from(key).unwrap(),
            )
            .unwrap(),
        value,
    );

    // Negative flow: not enough fee paid on L1.
    let tx_no_fee = l1_handler_tx(&calldata, Fee(0));
    let error = tx_no_fee.execute(state, block_context, true, true).unwrap_err();
    // Today, we check that the paid_fee is positive, no matter what was the actual fee.
    assert_matches!(
        error,
        TransactionExecutionError::TransactionFeeError(
            TransactionFeeError::InsufficientL1Fee { paid_fee, actual_fee, })
            if paid_fee == Fee(0) && actual_fee == Fee(1741300000000000)
    );
}

#[test]
fn test_execute_tx_with_invalid_transaction_version() {
    let cairo_version = CairoVersion::Cairo0;
    let account = FeatureContract::AccountWithoutValidations(cairo_version);
    let test_contract = FeatureContract::TestContract(cairo_version);
    let block_context = &BlockContext::create_for_account_testing();
    let state = &mut test_state(block_context, BALANCE, &[(account, 1), (test_contract, 1)]);
    let invalid_version = 12345_u64;
    let calldata = create_calldata(
        test_contract.get_instance_address(0),
        "test_tx_version",
        &[stark_felt!(invalid_version)],
    );
    let account_tx = account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(MAX_FEE),
        sender_address: account.get_instance_address(0),
        calldata,
    });

    let execution_info = account_tx.execute(state, block_context, true, true).unwrap();
    assert!(
        execution_info
            .revert_error
            .unwrap()
            .contains(format!("ASSERT_EQ instruction failed: {} != 1.", invalid_version).as_str())
    );
}
