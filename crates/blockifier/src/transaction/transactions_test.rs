use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use assert_matches::assert_matches;
use cairo_vm::vm::runners::builtin_runner::{HASH_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use itertools::concat;
use num_traits::Pow;
use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::core::{ChainId, ClassHash, ContractAddress, EthAddress, Nonce, PatriciaKey};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, EventContent, EventData, EventKey, Fee, L2ToL1Payload, TransactionHash,
    TransactionSignature, TransactionVersion,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key};
use starknet_types_core::felt::Felt;
use strum::IntoEnumIterator;
use test_case::test_case;

use crate::abi::abi_utils::{
    get_fee_token_var_address, get_storage_var_address, selector_from_name,
};
use crate::abi::constants as abi_constants;
use crate::abi::sierra_types::next_storage_key;
use crate::block_context::{BlockContext, ChainInfo, FeeTokenAddresses};
use crate::execution::call_info::{
    CallExecution, CallInfo, MessageToL1, OrderedEvent, OrderedL2ToL1Message, Retdata,
};
use crate::execution::entry_point::{CallEntryPoint, CallType};
use crate::execution::errors::{EntryPointExecutionError, VirtualMachineExecutionError};
use crate::fee::fee_utils::calculate_tx_fee;
use crate::fee::gas_usage::{
    calculate_tx_gas_and_blob_gas_usage, estimate_minimal_l1_gas, get_onchain_data_cost,
};
use crate::state::cached_state::{CachedState, StateChangesCount};
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::cached_state::create_test_state;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::declare::declare_tx;
use crate::test_utils::deploy_account::deploy_account_tx;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::invoke::{invoke_tx, InvokeTxArgs};
use crate::test_utils::prices::Prices;
use crate::test_utils::{
    create_calldata, test_erc20_sequencer_balance_key, CairoVersion, NonceManager, SaltManager,
    BALANCE, CHAIN_ID_NAME, CURRENT_BLOCK_NUMBER, CURRENT_BLOCK_TIMESTAMP, MAX_FEE,
    MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS,
    TEST_SEQUENCER_ADDRESS,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants;
use crate::transaction::errors::{
    TransactionExecutionError, TransactionFeeError, TransactionPreValidationError,
};
use crate::transaction::objects::{
    AccountTransactionContext, FeeType, GasAndBlobGasUsages, HasRelatedFeeType, ResourcesMapping,
    TransactionExecutionInfo,
};
use crate::transaction::test_utils::{
    account_invoke_tx, create_account_tx_for_validate_test, l1_resource_bounds,
    FaultyAccountTxCreatorArgs, CALL_CONTRACT, GET_BLOCK_HASH, INVALID, VALID,
};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transactions::{ExecutableTransaction, L1HandlerTransaction};
use crate::{
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
        CairoVersion::Cairo1 => retdata!(Felt::from_hex_unchecked(constants::VALIDATE_RETDATA)),
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
    fee_type: &FeeType,
    expected_fee_token_class_hash: ClassHash,
) -> Option<CallInfo> {
    let expected_sequencer_address = block_context.block_info.sequencer_address;
    let expected_sequencer_address_felt = expected_sequencer_address.0.to_felt();
    // The least significant 128 bits of the expected amount transferred.
    let lsb_expected_amount = Felt::from(actual_fee.0);
    // The most significant 128 bits of the expected amount transferred.
    let msb_expected_amount = Felt::ZERO;
    let storage_address = block_context.chain_info.fee_token_address(fee_type);
    let expected_fee_transfer_call = CallEntryPoint {
        class_hash: Some(expected_fee_token_class_hash),
        code_address: None,
        entry_point_type: EntryPointType::External,
        entry_point_selector: selector_from_name(constants::TRANSFER_ENTRY_POINT_NAME),
        calldata: calldata![
            expected_sequencer_address_felt, // Recipient.
            lsb_expected_amount,
            msb_expected_amount
        ],
        storage_address,
        caller_address: account_address,
        call_type: CallType::Call,
        initial_gas: abi_constants::INITIAL_GAS_COST,
    };
    let expected_fee_sender_address = account_address.0.to_felt();
    let expected_fee_transfer_event = OrderedEvent {
        order: 0,
        event: EventContent {
            keys: vec![EventKey(selector_from_name(constants::TRANSFER_EVENT_NAME).0)],
            data: EventData(vec![
                expected_fee_sender_address,
                expected_sequencer_address_felt, // Recipient.
                lsb_expected_amount,
                msb_expected_amount,
            ]),
        },
    };

    let sender_balance_key_low = get_fee_token_var_address(account_address);
    let sender_balance_key_high =
        next_storage_key(&sender_balance_key_low).expect("Cannot get sender balance high key.");
    let sequencer_balance_key_low = get_fee_token_var_address(expected_sequencer_address);
    let sequencer_balance_key_high = next_storage_key(&sequencer_balance_key_low)
        .expect("Cannot get sequencer balance high key.");
    Some(CallInfo {
        call: expected_fee_transfer_call,
        execution: CallExecution {
            retdata: retdata![Felt::from(constants::FELT_TRUE)],
            events: vec![expected_fee_transfer_event],
            ..Default::default()
        },
        vm_resources: Prices::FeeTransfer(account_address, *fee_type).into(),
        // We read sender balance, write (which starts with read) sender balance, then the same for
        // recipient. We read Uint256(BALANCE, 0) twice, then Uint256(0, 0) twice.
        storage_read_values: vec![
            Felt::from(BALANCE),
            Felt::ZERO,
            Felt::from(BALANCE),
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
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
    chain_info: &ChainInfo,
    expected_actual_fee: Fee,
    erc20_account_balance_key: StorageKey,
    fee_type: &FeeType,
    initial_account_balance_eth: u128,
    initial_account_balance_strk: u128,
) {
    // Expected balances of account and sequencer, per fee type.
    let (expected_sequencer_balance_eth, expected_sequencer_balance_strk) = match fee_type {
        FeeType::Eth => (Felt::from(expected_actual_fee.0), Felt::ZERO),
        FeeType::Strk => (Felt::ZERO, Felt::from(expected_actual_fee.0)),
    };
    let mut expected_account_balance_eth = initial_account_balance_eth;
    let mut expected_account_balance_strk = initial_account_balance_strk;
    if fee_type == &FeeType::Eth {
        expected_account_balance_eth -= expected_actual_fee.0;
    } else {
        expected_account_balance_strk -= expected_actual_fee.0;
    }

    // Verify balances of both accounts, of both fee types, are as expected.
    let FeeTokenAddresses { eth_fee_token_address, strk_fee_token_address } =
        chain_info.fee_token_addresses;
    for (fee_address, expected_account_balance, expected_sequencer_balance) in [
        (eth_fee_token_address, expected_account_balance_eth, expected_sequencer_balance_eth),
        (strk_fee_token_address, expected_account_balance_strk, expected_sequencer_balance_strk),
    ] {
        let account_balance = state.get_storage_at(fee_address, erc20_account_balance_key).unwrap();
        assert_eq!(account_balance, Felt::from(expected_account_balance));
        assert_eq!(
            state.get_storage_at(fee_address, test_erc20_sequencer_balance_key()).unwrap(),
            expected_sequencer_balance
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
        &[Felt::TWO], // Calldata: num.
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
    let chain_info = &block_context.chain_info;
    let state = &mut test_state(chain_info, BALANCE, &[(account_contract, 1), (test_contract, 1)]);
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
    let expected_return_result_calldata = vec![Felt::TWO];
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
        fee_type,
        FeatureContract::ERC20.get_class_hash(),
    );

    let expected_execution_info = TransactionExecutionInfo {
        validate_call_info: expected_validate_call_info,
        execute_call_info: expected_execute_call_info,
        fee_transfer_call_info: expected_fee_transfer_call_info,
        actual_fee: expected_actual_fee,
        actual_resources: ResourcesMapping(HashMap::from([
            (
                abi_constants::GAS_USAGE.to_string(),
                get_onchain_data_cost(StateChangesCount {
                    n_storage_updates: 1,
                    n_modified_contracts: 1,
                    ..StateChangesCount::default()
                }),
            ),
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
    assert_eq!(nonce_from_state, Nonce(Felt::ONE));

    // Test final balances.
    validate_final_balances(
        state,
        chain_info,
        expected_actual_fee,
        get_fee_token_var_address(account_contract_address),
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
    index: Felt,
    expected_counters: [Felt; 2],
    expected_ec_point: [Felt; 2],
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

#[rstest]
fn test_invoke_tx_advanced_operations(
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let block_context = &BlockContext::create_for_account_testing();
    let account = FeatureContract::AccountWithoutValidations(cairo_version);
    let test_contract = FeatureContract::TestContract(cairo_version);
    let state =
        &mut test_state(&block_context.chain_info, BALANCE, &[(account, 1), (test_contract, 1)]);
    let account_address = account.get_instance_address(0);
    let contract_address = test_contract.get_instance_address(0);
    let index = Felt::from(123_u32);
    let base_tx_args = invoke_tx_args! {
        max_fee: Fee(MAX_FEE),
        sender_address: account_address,
    };

    // Invoke advance_counter function.
    let mut nonce_manager = NonceManager::default();
    let counter_diffs = [101_u32, 102_u32];
    let initial_counters = [Felt::from(counter_diffs[0]), Felt::from(counter_diffs[1])];
    let calldata_args = vec![index, initial_counters[0], initial_counters[1]];

    let account_tx = account_invoke_tx(invoke_tx_args! {
        nonce: nonce_manager.next(account_address),
        calldata:
            create_calldata(contract_address, "advance_counter", &calldata_args),
        ..base_tx_args.clone()
    });
    account_tx.execute(state, block_context, true, true).unwrap();

    let next_nonce = nonce_manager.next(account_address);
    let initial_ec_point = [Felt::ZERO, Felt::ZERO];
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
        contract_address.0.to_felt(),
        index,
        Felt::from(xor_values[0]),
        Felt::from(xor_values[1]),
    ];

    let account_tx = account_invoke_tx(invoke_tx_args! {
        nonce: next_nonce,
        calldata:
            create_calldata(contract_address, "call_xor_counters", &calldata_args),
        ..base_tx_args.clone()
    });
    account_tx.execute(state, block_context, true, true).unwrap();

    let expected_counters = [
        Felt::from(counter_diffs[0] ^ xor_values[0]),
        Felt::from(counter_diffs[1] ^ xor_values[1]),
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
        Felt::from_bytes_be(&[
            0x05, 0x07, 0xF8, 0x28, 0xEA, 0xE0, 0x0C, 0x08, 0xED, 0x10, 0x60, 0x5B, 0xAA, 0xD4,
            0x80, 0xB7, 0x4B, 0x0E, 0x9B, 0x61, 0x9C, 0x1A, 0x2C, 0x53, 0xFB, 0x75, 0x86, 0xE3,
            0xEE, 0x1A, 0x82, 0xBA,
        ]),
        Felt::from_bytes_be(&[
            0x05, 0x43, 0x9A, 0x5D, 0xC0, 0x8C, 0xC1, 0x35, 0x64, 0x11, 0xA4, 0x57, 0x8F, 0x50,
            0x71, 0x54, 0xB4, 0x84, 0x7B, 0xAA, 0x73, 0x70, 0x68, 0x17, 0x1D, 0xFA, 0x6C, 0x8A,
            0xB3, 0x49, 0x9D, 0x8B,
        ]),
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
    let signature_values =
        vec![Felt::from_hex_unchecked("0x200"), Felt::from_hex_unchecked("0x300")];
    let signature = TransactionSignature(signature_values.clone());

    let account_tx = account_invoke_tx(invoke_tx_args! {
        signature,
        nonce: next_nonce,
        calldata:
            create_calldata(contract_address, "add_signature_to_counters", &[index]),
        ..base_tx_args.clone()
    });
    account_tx.execute(state, block_context, true, true).unwrap();

    let expected_counters =
        [expected_counters[0] + signature_values[0], expected_counters[1] + signature_values[1]];
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
    let to_address = Felt::from(85);
    let account_tx = account_invoke_tx(invoke_tx_args! {
        nonce: next_nonce,
        calldata:
            create_calldata(contract_address, "send_message", &[to_address]),
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
            to_address: EthAddress::try_from(to_address).unwrap(),
            payload: L2ToL1Payload(vec![Felt::from(12_u32), Felt::from(34_u32)]),
        },
    };
    assert_eq!(
        expected_msg,
        execution_info.execute_call_info.unwrap().inner_calls[0].execution.l2_to_l1_messages[0]
    );
}

#[rstest]
#[case(TransactionVersion::ONE, FeeType::Eth)]
#[case(TransactionVersion::THREE, FeeType::Strk)]
fn test_state_get_fee_token_balance(
    #[case] tx_version: TransactionVersion,
    #[case] fee_type: FeeType,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] account_version: CairoVersion,
) {
    let block_context = &BlockContext::create_for_account_testing();
    let chain_info = &block_context.chain_info;
    let account = FeatureContract::AccountWithoutValidations(account_version);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let state = &mut test_state(chain_info, BALANCE, &[(account, 1), (test_contract, 1)]);
    let account_address = account.get_instance_address(0);
    let (mint_high, mint_low) = (Felt::from(54_u8), Felt::from(39_u8));
    let recipient = Felt::from(10_u8);
    let fee_token_address = chain_info.fee_token_address(&fee_type);

    // Give the account mint privileges.
    state
        .set_storage_at(
            fee_token_address,
            get_storage_var_address("permitted_minter", &[]),
            account_address.0.to_felt(),
        )
        .unwrap();

    // Mint some tokens.
    let execute_calldata =
        create_calldata(fee_token_address, "permissionedMint", &[recipient, mint_low, mint_high]);
    let account_tx = account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(MAX_FEE),
        sender_address: account_address,
        calldata: execute_calldata,
        version: tx_version,
        nonce: Nonce::default(),
    });
    account_tx.execute(state, block_context, true, true).unwrap();

    // Get balance from state, and validate.
    let (low, high) =
        state.get_fee_token_balance(contract_address!(recipient), fee_token_address).unwrap();

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
    let state = &mut test_state(
        &block_context.chain_info,
        BALANCE,
        &[(account_contract, 1), (test_contract, 1)],
    );
    let account_contract_address = account_contract.get_instance_address(0);
    let default_args =
        default_invoke_tx_args(account_contract_address, test_contract.get_instance_address(0));

    let invalid_max_fee = Fee(BALANCE + 1);
    // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion works.
    let balance_over_gas_price: u64 =
        (BALANCE / MAX_L1_GAS_PRICE).try_into().expect("Failed to convert u128 to u64.");
    let invalid_resource_bounds = l1_resource_bounds(balance_over_gas_price + 1, MAX_L1_GAS_PRICE);

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
        deploy_account_tx_args! {
            max_fee: Fee(MAX_FEE),
            class_hash: test_contract.get_class_hash()
        },
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

// TODO(Aner, 21/01/24) modify for 4844 (taking blob_gas into account).
#[test_case(CairoVersion::Cairo0; "With Cairo0 account")]
#[test_case(CairoVersion::Cairo1; "With Cairo1 account")]
fn test_insufficient_resource_bounds(account_cairo_version: CairoVersion) {
    let block_context = &BlockContext::create_for_account_testing();
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let state = &mut test_state(
        &block_context.chain_info,
        BALANCE,
        &[(account_contract, 1), (test_contract, 1)],
    );
    let valid_invoke_tx_args = default_invoke_tx_args(
        account_contract.get_instance_address(0),
        test_contract.get_instance_address(0),
    );

    // The minimal gas estimate does not depend on tx version.
    let minimal_l1_gas =
        estimate_minimal_l1_gas(block_context, &account_invoke_tx(valid_invoke_tx_args.clone()))
            .unwrap()
            .gas_usage;

    // Test V1 transaction.

    let gas_prices = &block_context.block_info.gas_prices;
    // TODO(Aner, 21/01/24) change to linear combination.
    let minimal_fee = Fee(minimal_l1_gas * gas_prices.eth_l1_gas_price);
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
    let actual_strk_l1_gas_price = gas_prices.strk_l1_gas_price;

    // Max L1 gas amount too low.
    // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion works.
    let insufficient_max_l1_gas_amount =
        (minimal_l1_gas - 1).try_into().expect("Failed to convert u128 to u64.");
    let invalid_v3_tx = account_invoke_tx(invoke_tx_args! {
        resource_bounds: l1_resource_bounds(insufficient_max_l1_gas_amount, actual_strk_l1_gas_price),
        version: TransactionVersion::THREE,
        ..valid_invoke_tx_args.clone()
    });
    let execution_error = invalid_v3_tx.execute(state, block_context, true, true).unwrap_err();
    // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion works.
    let minimal_l1_gas_as_u64 =
        u64::try_from(minimal_l1_gas).expect("Failed to convert u128 to u64.");
    assert_matches!(
        execution_error,
        TransactionExecutionError::TransactionPreValidationError(
            TransactionPreValidationError::TransactionFeeError(
                TransactionFeeError::MaxL1GasAmountTooLow{
                    max_l1_gas_amount, minimal_l1_gas_amount }))
        if max_l1_gas_amount == insufficient_max_l1_gas_amount &&
        minimal_l1_gas_amount == minimal_l1_gas_as_u64
    );

    // Max L1 gas price too low.
    let insufficient_max_l1_gas_price = actual_strk_l1_gas_price - 1;
    let invalid_v3_tx = account_invoke_tx(invoke_tx_args! {
        // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion
        // works.
        resource_bounds: l1_resource_bounds(minimal_l1_gas.try_into().expect("Failed to convert u128 to u64."), insufficient_max_l1_gas_price),
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

// TODO(Aner, 21/01/24) modify test for 4844.
#[test_case(CairoVersion::Cairo0; "With Cairo0 account")]
#[test_case(CairoVersion::Cairo1; "With Cairo1 account")]
fn test_actual_fee_gt_resource_bounds(account_cairo_version: CairoVersion) {
    let block_context = &BlockContext::create_for_account_testing();
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let state = &mut test_state(
        &block_context.chain_info,
        BALANCE,
        &[(account_contract, 1), (test_contract, 1)],
    );
    let invoke_tx_args = default_invoke_tx_args(
        account_contract.get_instance_address(0),
        test_contract.get_instance_address(0),
    );

    let minimal_l1_gas =
        estimate_minimal_l1_gas(block_context, &account_invoke_tx(invoke_tx_args.clone()))
            .unwrap()
            .gas_usage;
    let minimal_fee = Fee(minimal_l1_gas * block_context.block_info.gas_prices.eth_l1_gas_price);
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
    let state = &mut test_state(
        &block_context.chain_info,
        BALANCE,
        &[(account_contract, 1), (test_contract, 1)],
    );
    let valid_invoke_tx_args = default_invoke_tx_args(
        account_contract.get_instance_address(0),
        test_contract.get_instance_address(0),
    );
    let mut transactional_state = CachedState::create_transactional(state);

    // Strict, negative flow: account nonce = 0, incoming tx nonce = 1.
    let invalid_nonce = Nonce(Felt::ONE);
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
    let valid_nonce = Nonce(Felt::ONE);
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
    let invalid_nonce = Nonce(Felt::ZERO);
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
        (valid_invoke_tx_args.sender_address, Nonce(Felt::ONE), invalid_nonce)
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

/// Returns the expected used L1 gas due to execution of a declare transaction.
fn declare_expected_l1_gas_usage(version: TransactionVersion) -> usize {
    let state_changes_count = if version == TransactionVersion::ZERO {
        StateChangesCount {
            n_storage_updates: 1, // Sender balance.
            ..StateChangesCount::default()
        }
    } else if version == TransactionVersion::ONE {
        StateChangesCount {
            n_storage_updates: 1,    // Sender balance.
            n_modified_contracts: 1, // Nonce.
            ..StateChangesCount::default()
        }
    } else if version == TransactionVersion::TWO || version == TransactionVersion::THREE {
        StateChangesCount {
            n_storage_updates: 1,             // Sender balance.
            n_modified_contracts: 1,          // Nonce.
            n_compiled_class_hash_updates: 1, // Also set compiled class hash.
            ..StateChangesCount::default()
        }
    } else {
        panic!("Unsupported version {version:?}.")
    };

    get_onchain_data_cost(state_changes_count)
}

#[rstest]
#[case(TransactionVersion::ZERO, CairoVersion::Cairo0)]
#[case(TransactionVersion::ONE, CairoVersion::Cairo0)]
#[case(TransactionVersion::TWO, CairoVersion::Cairo1)]
#[case(TransactionVersion::THREE, CairoVersion::Cairo1)]
fn test_declare_tx(
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] account_cairo_version: CairoVersion,
    #[case] tx_version: TransactionVersion,
    #[case] empty_contract_version: CairoVersion,
) {
    let block_context = &BlockContext::create_for_account_testing();
    let empty_contract = FeatureContract::Empty(empty_contract_version);
    let account = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let chain_info = &block_context.chain_info;
    let state = &mut test_state(chain_info, BALANCE, &[(account, 1)]);
    let class_hash = empty_contract.get_class_hash();
    let contract_class = empty_contract.get_class();
    let sender_address = account.get_instance_address(0);

    let account_tx = declare_tx(
        declare_tx_args! {
            max_fee: Fee(MAX_FEE),
            sender_address,
            version: tx_version,
            resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
            class_hash,
        },
        contract_class.clone(),
    );

    // Check state before transaction application.
    assert_matches!(
        state.get_compiled_contract_class(class_hash).unwrap_err(),
        StateError::UndeclaredClassHash(undeclared_class_hash) if
        undeclared_class_hash == class_hash
    );
    let fee_type = &account_tx.fee_type();
    let actual_execution_info = account_tx.execute(state, block_context, true, true).unwrap();

    // Build expected validate call info.
    let expected_validate_call_info = declare_validate_callinfo(
        tx_version,
        account_cairo_version,
        class_hash,
        account.get_class_hash(),
        sender_address,
    );

    // Build expected fee transfer call info.
    let expected_actual_fee =
        calculate_tx_fee(&actual_execution_info.actual_resources, block_context, fee_type).unwrap();
    let expected_fee_transfer_call_info = expected_fee_transfer_call_info(
        block_context,
        sender_address,
        expected_actual_fee,
        fee_type,
        FeatureContract::ERC20.get_class_hash(),
    );

    let expected_execution_info = TransactionExecutionInfo {
        validate_call_info: expected_validate_call_info,
        execute_call_info: None,
        fee_transfer_call_info: expected_fee_transfer_call_info,
        actual_fee: expected_actual_fee,
        revert_error: None,
        actual_resources: ResourcesMapping(HashMap::from([
            (abi_constants::GAS_USAGE.to_string(), declare_expected_l1_gas_usage(tx_version)),
            (HASH_BUILTIN_NAME.to_string(), 15),
            (
                RANGE_CHECK_BUILTIN_NAME.to_string(),
                declare_expected_range_check_builtin(tx_version, account_cairo_version),
            ),
            (
                abi_constants::N_STEPS_RESOURCE.to_string(),
                declare_n_steps(tx_version, account_cairo_version),
            ),
        ])),
    };

    // Test execution info result.
    assert_eq!(actual_execution_info, expected_execution_info);

    // Test nonce update. V0 transactions do not update nonce.
    let expected_nonce =
        Nonce(Felt::from(if tx_version == TransactionVersion::ZERO { 0_u8 } else { 1_u8 }));
    let nonce_from_state = state.get_nonce_at(sender_address).unwrap();
    assert_eq!(nonce_from_state, expected_nonce);

    // Test final balances.
    validate_final_balances(
        state,
        chain_info,
        expected_actual_fee,
        get_fee_token_var_address(sender_address),
        fee_type,
        BALANCE,
        BALANCE,
    );

    // Verify class declaration.
    let contract_class_from_state = state.get_compiled_contract_class(class_hash).unwrap();
    assert_eq!(contract_class_from_state, contract_class);
}

#[rstest]
#[case(83, 3893, CairoVersion::Cairo0)]
#[case(85, 3949, CairoVersion::Cairo1)]
fn test_deploy_account_tx(
    #[case] expected_range_check_builtin: usize,
    #[case] expected_n_steps_resource: usize,
    #[case] cairo_version: CairoVersion,
) {
    let block_context = &BlockContext::create_for_account_testing();
    let chain_info = &block_context.chain_info;
    let mut nonce_manager = NonceManager::default();
    let account = FeatureContract::AccountWithoutValidations(cairo_version);
    let account_class_hash = account.get_class_hash();
    let state = &mut test_state(chain_info, BALANCE, &[(account, 1)]);
    let deploy_account = deploy_account_tx(
        deploy_account_tx_args! { max_fee: Fee(MAX_FEE), class_hash: account_class_hash },
        &mut nonce_manager,
    );

    // Extract deploy account transaction fields for testing, as it is consumed when creating an
    // account transaction.
    let class_hash = deploy_account.class_hash();
    let deployed_account_address = deploy_account.contract_address;
    let constructor_calldata = deploy_account.constructor_calldata();
    let salt = deploy_account.contract_address_salt();

    // Update the balance of the about to be deployed account contract in the erc20 contract, so it
    // can pay for the transaction execution.
    let deployed_account_balance_key = get_fee_token_var_address(deployed_account_address);
    for fee_type in FeeType::iter() {
        state
            .set_storage_at(
                chain_info.fee_token_address(&fee_type),
                deployed_account_balance_key,
                Felt::from(BALANCE),
            )
            .unwrap();
    }

    let account_tx = AccountTransaction::DeployAccount(deploy_account);
    let fee_type = &account_tx.fee_type();
    let actual_execution_info = account_tx.execute(state, block_context, true, true).unwrap();

    // Build expected validate call info.
    let validate_calldata =
        concat(vec![vec![class_hash.0, salt.0], (*constructor_calldata.0).clone()]);
    let expected_gas_consumed = 0;
    let expected_validate_call_info = expected_validate_call_info(
        account_class_hash,
        constants::VALIDATE_DEPLOY_ENTRY_POINT_NAME,
        expected_gas_consumed,
        Calldata(validate_calldata.into()),
        deployed_account_address,
        cairo_version,
    );

    // Build expected execute call info.
    let expected_execute_call_info = Some(CallInfo {
        call: CallEntryPoint {
            class_hash: Some(account_class_hash),
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
        fee_type,
        FeatureContract::ERC20.get_class_hash(),
    );

    let expected_execution_info = TransactionExecutionInfo {
        validate_call_info: expected_validate_call_info,
        execute_call_info: expected_execute_call_info,
        fee_transfer_call_info: expected_fee_transfer_call_info,
        actual_fee: expected_actual_fee,
        revert_error: None,
        actual_resources: ResourcesMapping(HashMap::from([
            (
                abi_constants::GAS_USAGE.to_string(),
                get_onchain_data_cost(StateChangesCount {
                    n_storage_updates: 1,
                    n_modified_contracts: 1,
                    n_class_hash_updates: 1,
                    ..StateChangesCount::default()
                }),
            ),
            (HASH_BUILTIN_NAME.to_string(), 23),
            (RANGE_CHECK_BUILTIN_NAME.to_string(), expected_range_check_builtin),
            (abi_constants::N_STEPS_RESOURCE.to_string(), expected_n_steps_resource),
        ])),
    };

    // Test execution info result.
    assert_eq!(actual_execution_info, expected_execution_info);

    // Test nonce update.
    let nonce_from_state = state.get_nonce_at(deployed_account_address).unwrap();
    assert_eq!(nonce_from_state, Nonce(Felt::ONE));

    // Test final balances.
    validate_final_balances(
        state,
        chain_info,
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
    let deploy_account = deploy_account_tx(
        deploy_account_tx_args! { max_fee: Fee(MAX_FEE), class_hash: account_class_hash },
        &mut nonce_manager,
    );
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
    let block_context = &BlockContext::create_for_account_testing();
    let chain_info = &block_context.chain_info;
    let state = &mut test_state(chain_info, BALANCE, &[]);
    let mut nonce_manager = NonceManager::default();
    let undeclared_hash = class_hash!(0xdeadbeefu64);
    let deploy_account = deploy_account_tx(
        deploy_account_tx_args! { max_fee: Fee(MAX_FEE), class_hash: undeclared_hash },
        &mut nonce_manager,
    );

    // Fund account, so as not to fail pre-validation.
    state
        .set_storage_at(
            chain_info.fee_token_address(&FeeType::Eth),
            get_fee_token_var_address(deploy_account.contract_address),
            Felt::from(BALANCE),
        )
        .unwrap();

    let account_tx = AccountTransaction::DeployAccount(deploy_account);
    let error = account_tx.execute(state, block_context, true, true).unwrap_err();
    assert_matches!(
        error,
        TransactionExecutionError::ContractConstructorExecutionFailed(
            EntryPointExecutionError::StateError(StateError::UndeclaredClassHash(class_hash))
        )
        if class_hash == undeclared_hash
    );
}

// TODO(Arni, 1/1/2024): Consider converting this test to use V3 txs.
#[rstest]
#[case::validate(TransactionType::InvokeFunction, false)]
#[case::validate_declare(TransactionType::Declare, false)]
#[case::validate_deploy(TransactionType::DeployAccount, false)]
#[case::constructor(TransactionType::DeployAccount, true)]
fn test_validate_accounts_tx(
    #[case] tx_type: TransactionType,
    #[case] validate_constructor: bool,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let block_context = &BlockContext::create_for_account_testing();
    let account_balance = 0;
    let faulty_account = FeatureContract::FaultyAccount(cairo_version);
    let sender_address = faulty_account.get_instance_address(0);
    let class_hash = faulty_account.get_class_hash();
    let state = &mut test_state(&block_context.chain_info, account_balance, &[(faulty_account, 1)]);
    let salt_manager = &mut SaltManager::default();

    let default_args = FaultyAccountTxCreatorArgs {
        tx_type,
        sender_address,
        class_hash,
        validate_constructor,
        ..Default::default()
    };

    // Negative flows.

    // Logic failure.
    let account_tx = create_account_tx_for_validate_test(
        &mut NonceManager::default(),
        FaultyAccountTxCreatorArgs {
            scenario: INVALID,
            contract_address_salt: salt_manager.next_salt(),
            ..default_args
        },
    );
    let error = account_tx.execute(state, block_context, true, true).unwrap_err();
    check_transaction_execution_error_for_invalid_scenario!(
        cairo_version,
        error,
        validate_constructor,
    );

    // Trying to call another contract (forbidden).
    let account_tx = create_account_tx_for_validate_test(
        &mut NonceManager::default(),
        FaultyAccountTxCreatorArgs {
            scenario: CALL_CONTRACT,
            additional_data: Some(Felt::from_hex_unchecked("0x1991")), /* Some address different
                                                                        * than the
                                                                        * address of
                                                                        * faulty_account. */
            contract_address_salt: salt_manager.next_salt(),
            ..default_args
        },
    );
    let error = account_tx.execute(state, block_context, true, true).unwrap_err();
    check_transaction_execution_error_for_custom_hint!(
        &error,
        "Unauthorized syscall call_contract in execution mode Validate.",
        validate_constructor,
    );

    if let CairoVersion::Cairo1 = cairo_version {
        // Trying to use the syscall get_block_hash (forbidden).
        // TODO(Arni, 12/12/2023): Test this scenario with the constructor.
        let account_tx = create_account_tx_for_validate_test(
            &mut NonceManager::default(),
            FaultyAccountTxCreatorArgs {
                scenario: GET_BLOCK_HASH,
                contract_address_salt: salt_manager.next_salt(),
                ..default_args
            },
        );
        let error = account_tx.execute(state, block_context, true, true).unwrap_err();
        check_transaction_execution_error_for_custom_hint!(
            &error,
            "Unauthorized syscall get_block_hash in execution mode Validate.",
            validate_constructor,
        );
    }

    // Positive flows.

    // Valid logic.
    let nonce_manager = &mut NonceManager::default();
    let account_tx = create_account_tx_for_validate_test(
        nonce_manager,
        FaultyAccountTxCreatorArgs {
            scenario: VALID,
            contract_address_salt: salt_manager.next_salt(),
            ..default_args
        },
    );
    account_tx.execute(state, block_context, true, true).unwrap();

    if tx_type != TransactionType::DeployAccount {
        // Calling self (allowed).
        let account_tx = create_account_tx_for_validate_test(
            nonce_manager,
            FaultyAccountTxCreatorArgs {
                scenario: CALL_CONTRACT,
                additional_data: Some(sender_address.0.to_felt()),
                ..default_args
            },
        );
        account_tx.execute(state, block_context, true, true).unwrap();
    }
}

// Test that we exclude the fee token contract modification and adds the account’s balance change
// in the state changes.
// TODO(Aner, 21/01/24) modify for 4844 (taking blob_gas into account).
#[test]
fn test_calculate_tx_gas_usage() {
    let account_cairo_version = CairoVersion::Cairo0;
    let test_contract_cairo_version = CairoVersion::Cairo0;
    let block_context = &BlockContext::create_for_account_testing();
    let chain_info = &block_context.chain_info;
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(test_contract_cairo_version);
    let account_contract_address = account_contract.get_instance_address(0);
    let state = &mut test_state(chain_info, BALANCE, &[(account_contract, 1), (test_contract, 1)]);

    let account_tx = account_invoke_tx(default_invoke_tx_args(
        account_contract_address,
        test_contract.get_instance_address(0),
    ));
    let fee_token_address = chain_info.fee_token_address(&account_tx.fee_type());
    let tx_execution_info = account_tx.execute(state, block_context, true, true).unwrap();

    let n_storage_updates = 1; // For the account balance update.
    let n_modified_contracts = 1;
    let state_changes_count = StateChangesCount {
        n_storage_updates,
        n_class_hash_updates: 0,
        n_modified_contracts,
        n_compiled_class_hash_updates: 0,
    };

    let l1_gas_and_blob_gas_usage =
        calculate_tx_gas_and_blob_gas_usage(std::iter::empty(), state_changes_count, None).unwrap();
    let GasAndBlobGasUsages { gas_usage: l1_gas_usage, .. } = l1_gas_and_blob_gas_usage;
    assert_eq!(tx_execution_info.actual_resources.gas_usage() as u128, l1_gas_usage);

    // A tx that changes the account and some other balance in execute.
    let some_other_account_address = account_contract.get_instance_address(17);
    let execute_calldata = create_calldata(
        fee_token_address,
        constants::TRANSFER_ENTRY_POINT_NAME,
        &[
            some_other_account_address.0.to_felt(), // Calldata: recipient.
            Felt::TWO,                              // Calldata: lsb amount.
            Felt::ZERO,                             // Calldata: msb amount.
        ],
    );

    let account_tx = account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(MAX_FEE),
        sender_address: account_contract_address,
        calldata: execute_calldata,
        version: TransactionVersion::ONE,
        nonce: Nonce(Felt::ONE),
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

    let l1_gas_and_blob_gas_usage =
        calculate_tx_gas_and_blob_gas_usage(std::iter::empty(), state_changes_count, None).unwrap();
    let GasAndBlobGasUsages { gas_usage: l1_gas_usage, .. } = l1_gas_and_blob_gas_usage;
    assert_eq!(tx_execution_info.actual_resources.gas_usage() as u128, l1_gas_usage);
}

#[rstest]
fn test_valid_flag(
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] account_cairo_version: CairoVersion,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] test_contract_cairo_version: CairoVersion,
) {
    let block_context = &BlockContext::create_for_account_testing();
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(test_contract_cairo_version);
    let state = &mut test_state(
        &block_context.chain_info,
        BALANCE,
        &[(account_contract, 1), (test_contract, 1)],
    );

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
    let state = &mut test_state(
        &block_context.chain_info,
        account_balance,
        &[(account, 1), (test_contract, 1)],
    );
    let mut version = Felt::ONE;
    if only_query {
        let query_version_base = Pow::pow(Felt::TWO, constants::QUERY_VERSION_BASE_BIT);
        version += query_version_base;
    }
    let sender_address = account.get_instance_address(0);
    let test_contract_address = test_contract.get_instance_address(0);
    let max_fee = Fee(MAX_FEE);
    let expected_tx_info = vec![
        version,                                                               /* Transaction
                                                                                * version. */
        sender_address.0.to_felt(), // Account address.
        Felt::from(max_fee.0),      // Max fee.
        Felt::ZERO,                 // Signature.
        Felt::ZERO,                 // Transaction hash.
        Felt::from_hex(&ChainId(CHAIN_ID_NAME.to_string()).as_hex()).unwrap(), // Chain ID.
        Felt::ZERO,                 // Nonce.
        Felt::ZERO,                 // Length of resource bounds array.
        Felt::ZERO,                 // Tip.
        Felt::ZERO,                 // Paymaster data.
        Felt::ZERO,                 // Nonce DA.
        Felt::ZERO,                 // Fee DA.
        Felt::ZERO,                 // Account data.
    ];
    let entry_point_selector = selector_from_name("test_get_execution_info");
    let expected_call_info = vec![
        sender_address.0.to_felt(),        // Caller address.
        test_contract_address.0.to_felt(), // Storage address.
        entry_point_selector.0,            // Entry point selector.
    ];
    let expected_block_info = [
        Felt::from(CURRENT_BLOCK_NUMBER),    // Block number.
        Felt::from(CURRENT_BLOCK_TIMESTAMP), // Block timestamp.
        Felt::from(TEST_SEQUENCER_ADDRESS),  // Sequencer address.
    ];
    let calldata_len =
        expected_block_info.len() + expected_tx_info.len() + expected_call_info.len();
    let execute_calldata = vec![
        test_contract_address.0.to_felt(), // Contract address.
        entry_point_selector.0,            // EP selector.
        // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion
        // works.
        Felt::from(u64::try_from(calldata_len).expect("Failed to convert usize to u64.")), /* Calldata length. */
    ];
    let execute_calldata = Calldata(
        [
            execute_calldata,
            expected_block_info.clone().to_vec(),
            expected_tx_info,
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
    let from_address = Felt::from_hex_unchecked("0x123");
    let key = Felt::from_hex_unchecked("0x876");
    let value = Felt::from_hex_unchecked("0x44");
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
        (abi_constants::GAS_USAGE.to_string(), 17675),
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
    let state =
        &mut test_state(&block_context.chain_info, BALANCE, &[(account, 1), (test_contract, 1)]);
    let invalid_version = 12345_u64;
    let calldata = create_calldata(
        test_contract.get_instance_address(0),
        "test_tx_version",
        &[Felt::from(invalid_version)],
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
