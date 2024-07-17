use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use assert_matches::assert_matches;
use cairo_felt::Felt252;
use cairo_vm::vm::runners::builtin_runner::{HASH_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use num_traits::Pow;
use once_cell::sync::Lazy;
use pretty_assertions::assert_eq;
use rstest::{fixture, rstest};
use starknet_api::core::{ChainId, ClassHash, ContractAddress, EthAddress, Nonce, PatriciaKey};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, EventContent, EventData, EventKey, Fee, L2ToL1Payload, TransactionSignature,
    TransactionVersion,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};
use strum::IntoEnumIterator;

use crate::abi::abi_utils::{
    get_fee_token_var_address, get_storage_var_address, selector_from_name,
};
use crate::abi::constants as abi_constants;
use crate::abi::sierra_types::next_storage_key;
use crate::context::{BlockContext, ChainInfo, FeeTokenAddresses, TransactionContext};
use crate::execution::call_info::{
    CallExecution, CallInfo, MessageToL1, OrderedEvent, OrderedL2ToL1Message, Retdata,
};
use crate::execution::entry_point::{CallEntryPoint, CallType};
use crate::execution::errors::{ConstructorEntryPointExecutionError, EntryPointExecutionError};
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::execution::syscalls::hint_processor::EmitEventError;
use crate::execution::syscalls::SyscallSelector;
use crate::fee::fee_utils::calculate_tx_fee;
use crate::fee::gas_usage::{
    estimate_minimal_gas_vector, get_da_gas_cost, get_onchain_data_segment_length,
};
use crate::state::cached_state::{CachedState, StateChangesCount};
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::declare::declare_tx;
use crate::test_utils::deploy_account::deploy_account_tx;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::invoke::invoke_tx;
use crate::test_utils::prices::Prices;
use crate::test_utils::{
    create_calldata, create_trivial_calldata, get_syscall_resources, get_tx_resources,
    test_erc20_sequencer_balance_key, CairoVersion, NonceManager, SaltManager, BALANCE,
    CHAIN_ID_NAME, CURRENT_BLOCK_NUMBER, CURRENT_BLOCK_NUMBER_FOR_VALIDATE,
    CURRENT_BLOCK_TIMESTAMP, CURRENT_BLOCK_TIMESTAMP_FOR_VALIDATE, MAX_FEE, MAX_L1_GAS_AMOUNT,
    MAX_L1_GAS_PRICE, TEST_SEQUENCER_ADDRESS,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants;
use crate::transaction::errors::{
    TransactionExecutionError, TransactionFeeError, TransactionPreValidationError,
};
use crate::transaction::objects::{
    FeeType, GasVector, HasRelatedFeeType, StarknetResources, TransactionExecutionInfo,
    TransactionInfo, TransactionResources,
};
use crate::transaction::test_utils::{
    account_invoke_tx, block_context, calculate_class_info_for_testing,
    create_account_tx_for_validate_test, l1_resource_bounds, FaultyAccountTxCreatorArgs,
    CALL_CONTRACT, GET_BLOCK_HASH, GET_BLOCK_NUMBER, GET_BLOCK_TIMESTAMP, GET_EXECUTION_INFO,
    GET_SEQUENCER_ADDRESS, INVALID, VALID,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transactions::{ExecutableTransaction, L1HandlerTransaction};
use crate::versioned_constants::VersionedConstants;
use crate::{
    check_transaction_execution_error_for_custom_hint,
    check_transaction_execution_error_for_invalid_scenario, declare_tx_args,
    deploy_account_tx_args, invoke_tx_args, nonce, retdata,
};

static VERSIONED_CONSTANTS: Lazy<VersionedConstants> =
    Lazy::new(VersionedConstants::create_for_testing);

#[fixture]
fn tx_initial_gas() -> u64 {
    VERSIONED_CONSTANTS.tx_initial_gas()
}

#[fixture]
fn versioned_constants_for_account_testing() -> VersionedConstants {
    VERSIONED_CONSTANTS.clone()
}

struct ExpectedResultTestInvokeTx {
    resources: ExecutionResources,
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
    let n_steps = match (entry_point_selector_name, cairo_version) {
        (constants::VALIDATE_DEPLOY_ENTRY_POINT_NAME, CairoVersion::Cairo0) => 13_usize,
        (constants::VALIDATE_DEPLOY_ENTRY_POINT_NAME, CairoVersion::Cairo1) => 40_usize,
        (constants::VALIDATE_DECLARE_ENTRY_POINT_NAME, CairoVersion::Cairo0) => 12_usize,
        (constants::VALIDATE_DECLARE_ENTRY_POINT_NAME, CairoVersion::Cairo1) => 32_usize,
        (constants::VALIDATE_ENTRY_POINT_NAME, CairoVersion::Cairo0) => 21_usize,
        (constants::VALIDATE_ENTRY_POINT_NAME, CairoVersion::Cairo1) => 112_usize,
        (selector, _) => panic!("Selector {selector} is not a known validate selector."),
    };
    let resources = ExecutionResources {
        n_steps,
        n_memory_holes: 0,
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
            initial_gas: tx_initial_gas(),
        },
        // The account contract we use for testing has trivial `validate` functions.
        resources,
        execution: CallExecution { retdata, gas_consumed, ..Default::default() },
        ..Default::default()
    })
}

fn expected_fee_transfer_call_info(
    tx_context: &TransactionContext,
    account_address: ContractAddress,
    actual_fee: Fee,
    expected_fee_token_class_hash: ClassHash,
) -> Option<CallInfo> {
    let block_context = &tx_context.block_context;
    let fee_type = &tx_context.tx_info.fee_type();
    let expected_sequencer_address = block_context.block_info.sequencer_address;
    let expected_sequencer_address_felt = *expected_sequencer_address.0.key();
    // The least significant 128 bits of the expected amount transferred.
    let lsb_expected_amount = stark_felt!(actual_fee.0);
    // The most significant 128 bits of the expected amount transferred.
    let msb_expected_amount = stark_felt!(0_u8);
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
        initial_gas: block_context.versioned_constants.os_constants.gas_costs.initial_gas_cost,
    };
    let expected_fee_sender_address = *account_address.0.key();
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
            retdata: retdata![stark_felt!(constants::FELT_TRUE)],
            events: vec![expected_fee_transfer_event],
            ..Default::default()
        },
        resources: Prices::FeeTransfer(account_address, *fee_type).into(),
        // We read sender and recipient balance - Uint256(BALANCE, 0) then Uint256(0, 0).
        storage_read_values: vec![
            stark_felt!(BALANCE),
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

fn get_expected_cairo_resources(
    versioned_constants: &VersionedConstants,
    tx_type: TransactionType,
    starknet_resources: &StarknetResources,
    call_infos: Vec<&Option<CallInfo>>,
) -> ExecutionResources {
    let mut expected_cairo_resources = versioned_constants
        .get_additional_os_tx_resources(tx_type, starknet_resources, false)
        .unwrap();
    for call_info in call_infos {
        if let Some(call_info) = &call_info {
            expected_cairo_resources += &call_info.resources
        };
    }

    expected_cairo_resources
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
    let FeeTokenAddresses { eth_fee_token_address, strk_fee_token_address } =
        chain_info.fee_token_addresses;
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

fn add_kzg_da_resources_to_resources_mapping(
    target: &mut ExecutionResources,
    state_changes_count: &StateChangesCount,
    versioned_constants: &VersionedConstants,
    use_kzg_da: bool,
) {
    if !use_kzg_da {
        return;
    }

    let data_segment_length = get_onchain_data_segment_length(state_changes_count);
    let os_kzg_da_resources = versioned_constants.os_kzg_da_resources(data_segment_length);

    target.n_steps += os_kzg_da_resources.n_steps;

    os_kzg_da_resources.builtin_instance_counter.into_iter().for_each(|(key, value)| {
        target
            .builtin_instance_counter
            .entry(key.to_string())
            .and_modify(|v| *v += value)
            .or_insert(value);
    });
}

#[rstest]
#[case::with_cairo0_account(
    ExpectedResultTestInvokeTx{
        resources: &get_syscall_resources(SyscallSelector::CallContract) + &ExecutionResources {
            n_steps: 62,
            n_memory_holes:  0,
            builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 1)]),
        },
        validate_gas_consumed: 0,
        execute_gas_consumed: 0,
        inner_call_initial_gas: versioned_constants_for_account_testing().os_constants.gas_costs.initial_gas_cost,
    },
    CairoVersion::Cairo0)]
#[case::with_cairo1_account(
    ExpectedResultTestInvokeTx{
        resources: &get_syscall_resources(SyscallSelector::CallContract) + &ExecutionResources {
            n_steps: 219,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 8)]),
        },
        validate_gas_consumed: 4740, // The gas consumption results from parsing the input
            // arguments.
        execute_gas_consumed: 88160,
        inner_call_initial_gas: 9999707100,
    },
    CairoVersion::Cairo1)]
fn test_invoke_tx(
    #[case] expected_arguments: ExpectedResultTestInvokeTx,
    #[case] account_cairo_version: CairoVersion,
    #[values(false, true)] use_kzg_da: bool,
) {
    let block_context = &BlockContext::create_for_account_testing_with_kzg(use_kzg_da);
    let versioned_constants = &block_context.versioned_constants;
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let chain_info = &block_context.chain_info;
    let state = &mut test_state(chain_info, BALANCE, &[(account_contract, 1), (test_contract, 1)]);
    let test_contract_address = test_contract.get_instance_address(0);
    let account_contract_address = account_contract.get_instance_address(0);
    let invoke_tx = invoke_tx(invoke_tx_args! {
        sender_address: account_contract_address,
        calldata: create_trivial_calldata(test_contract_address),
        max_fee: Fee(MAX_FEE)
    });

    // Extract invoke transaction fields for testing, as it is consumed when creating an account
    // transaction.
    let calldata = Calldata(Arc::clone(&invoke_tx.calldata().0));
    let calldata_length = invoke_tx.calldata().0.len();
    let signature_length = invoke_tx.signature().0.len();
    let starknet_resources = StarknetResources::new(
        calldata_length,
        signature_length,
        0,
        StateChangesCount {
            n_storage_updates: 1,
            n_modified_contracts: 1,
            ..StateChangesCount::default()
        },
        None,
        std::iter::empty(),
    );
    let sender_address = invoke_tx.sender_address();

    let account_tx = AccountTransaction::Invoke(invoke_tx);
    let tx_context = block_context.to_tx_context(&account_tx);

    let actual_execution_info = account_tx.execute(state, block_context, true, true, None).unwrap();

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
        initial_gas: tx_initial_gas() - expected_arguments.validate_gas_consumed,
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
        resources: expected_arguments.resources,
        inner_calls: vec![CallInfo {
            call: expected_return_result_call,
            execution: CallExecution::from_retdata(expected_return_result_retdata),
            resources: ExecutionResources { n_steps: 23, n_memory_holes: 0, ..Default::default() },
            ..Default::default()
        }],
        ..Default::default()
    });

    // Build expected fee transfer call info.
    let fee_type = &tx_context.tx_info.fee_type();
    let expected_actual_fee =
        calculate_tx_fee(&actual_execution_info.actual_resources, block_context, fee_type).unwrap();
    let expected_fee_transfer_call_info = expected_fee_transfer_call_info(
        &tx_context,
        sender_address,
        expected_actual_fee,
        FeatureContract::ERC20.get_class_hash(),
    );

    let da_gas = starknet_resources.get_state_changes_cost(use_kzg_da);

    let expected_cairo_resources = get_expected_cairo_resources(
        versioned_constants,
        TransactionType::InvokeFunction,
        &starknet_resources,
        vec![&expected_validate_call_info, &expected_execute_call_info],
    );
    let state_changes_count = starknet_resources.state_changes_for_fee;
    let expected_actual_resources = TransactionResources {
        starknet_resources,
        vm_resources: expected_cairo_resources,
        ..Default::default()
    };
    let mut expected_execution_info = TransactionExecutionInfo {
        validate_call_info: expected_validate_call_info,
        execute_call_info: expected_execute_call_info,
        fee_transfer_call_info: expected_fee_transfer_call_info,
        actual_fee: expected_actual_fee,
        da_gas,
        actual_resources: expected_actual_resources,
        revert_error: None,
    };

    add_kzg_da_resources_to_resources_mapping(
        &mut expected_execution_info.actual_resources.vm_resources,
        &state_changes_count,
        versioned_constants,
        use_kzg_da,
    );

    // Test execution info result.
    assert_eq!(actual_execution_info, expected_execution_info);

    // Test nonce update.
    let nonce_from_state = state.get_nonce_at(sender_address).unwrap();
    assert_eq!(nonce_from_state, nonce!(1_u8));

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

#[rstest]
fn test_invoke_tx_advanced_operations(
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let block_context = &block_context;
    let account = FeatureContract::AccountWithoutValidations(cairo_version);
    let test_contract = FeatureContract::TestContract(cairo_version);
    let state =
        &mut test_state(&block_context.chain_info, BALANCE, &[(account, 1), (test_contract, 1)]);
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
    account_tx.execute(state, block_context, true, true, None).unwrap();

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
    account_tx.execute(state, block_context, true, true, None).unwrap();

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
    account_tx.execute(state, block_context, true, true, None).unwrap();

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
    account_tx.execute(state, block_context, true, true, None).unwrap();

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
    let execution_info = account_tx.execute(state, block_context, true, true, None).unwrap();
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

#[rstest]
#[case(TransactionVersion::ONE, FeeType::Eth)]
#[case(TransactionVersion::THREE, FeeType::Strk)]
fn test_state_get_fee_token_balance(
    block_context: BlockContext,
    #[case] tx_version: TransactionVersion,
    #[case] fee_type: FeeType,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] account_version: CairoVersion,
) {
    let block_context = &block_context;
    let chain_info = &block_context.chain_info;
    let account = FeatureContract::AccountWithoutValidations(account_version);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let state = &mut test_state(chain_info, BALANCE, &[(account, 1), (test_contract, 1)]);
    let account_address = account.get_instance_address(0);
    let (mint_high, mint_low) = (stark_felt!(54_u8), stark_felt!(39_u8));
    let recipient = stark_felt!(10_u8);
    let fee_token_address = chain_info.fee_token_address(&fee_type);

    // Give the account mint privileges.
    state
        .set_storage_at(
            fee_token_address,
            get_storage_var_address("permitted_minter", &[]),
            *account_address.0.key(),
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
    account_tx.execute(state, block_context, true, true, None).unwrap();

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
    match block_context.to_tx_context(&invalid_tx).tx_info {
        TransactionInfo::Deprecated(context) => {
            assert_matches!(
                invalid_tx.execute(state, block_context, true, true, None).unwrap_err(),
                TransactionExecutionError::TransactionPreValidationError(
                    TransactionPreValidationError::TransactionFeeError(
                        TransactionFeeError::MaxFeeExceedsBalance{ max_fee, .. }))
                if max_fee == context.max_fee
            );
        }
        TransactionInfo::Current(context) => {
            let l1_bounds = context.l1_resource_bounds().unwrap();
            assert_matches!(
                invalid_tx.execute(state, block_context, true, true, None).unwrap_err(),
                TransactionExecutionError::TransactionPreValidationError(
                    TransactionPreValidationError::TransactionFeeError(
                        TransactionFeeError::L1GasBoundsExceedBalance{ max_amount, max_price, .. }))
                if max_amount == l1_bounds.max_amount && max_price == l1_bounds.max_price_per_unit
            );
        }
    };
}

#[rstest]
fn test_max_fee_exceeds_balance(
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] account_cairo_version: CairoVersion,
) {
    let block_context = &block_context;
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let state = &mut test_state(
        &block_context.chain_info,
        BALANCE,
        &[(account_contract, 1), (test_contract, 1)],
    );
    let account_contract_address = account_contract.get_instance_address(0);
    let default_args = invoke_tx_args! {
        sender_address: account_contract_address,
        calldata: create_trivial_calldata(test_contract.get_instance_address(0)
    )};

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
    let class_info = calculate_class_info_for_testing(contract_to_declare.get_class());
    let invalid_tx = declare_tx(
        declare_tx_args! {
            class_hash: contract_to_declare.get_class_hash(),
            sender_address: account_contract_address,
            max_fee: invalid_max_fee,
        },
        class_info,
    );
    assert_failure_if_resource_bounds_exceed_balance(state, block_context, invalid_tx);
}

// TODO(Aner, 21/01/24) modify for 4844 (taking blob_gas into account).
#[rstest]
fn test_insufficient_resource_bounds(
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] account_cairo_version: CairoVersion,
) {
    let block_context = &block_context;
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let state = &mut test_state(
        &block_context.chain_info,
        BALANCE,
        &[(account_contract, 1), (test_contract, 1)],
    );
    let valid_invoke_tx_args = invoke_tx_args! {
        sender_address: account_contract.get_instance_address(0),
        calldata: create_trivial_calldata(test_contract.get_instance_address(0)),
        max_fee: Fee(MAX_FEE)
    };

    // The minimal gas estimate does not depend on tx version.
    let tx = &account_invoke_tx(valid_invoke_tx_args.clone());
    let minimal_l1_gas = estimate_minimal_gas_vector(block_context, tx).unwrap().l1_gas;

    // Test V1 transaction.

    let gas_prices = &block_context.block_info.gas_prices;
    // TODO(Aner, 21/01/24) change to linear combination.
    let minimal_fee = Fee(minimal_l1_gas * u128::from(gas_prices.eth_l1_gas_price));
    // Max fee too low (lower than minimal estimated fee).
    let invalid_max_fee = Fee(minimal_fee.0 - 1);
    let invalid_v1_tx = account_invoke_tx(
        invoke_tx_args! { max_fee: invalid_max_fee, ..valid_invoke_tx_args.clone() },
    );
    let execution_error =
        invalid_v1_tx.execute(state, block_context, true, true, None).unwrap_err();

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
        resource_bounds: l1_resource_bounds(insufficient_max_l1_gas_amount, actual_strk_l1_gas_price.into()),
        version: TransactionVersion::THREE,
        ..valid_invoke_tx_args.clone()
    });
    let execution_error =
        invalid_v3_tx.execute(state, block_context, true, true, None).unwrap_err();
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
    let insufficient_max_l1_gas_price = u128::from(actual_strk_l1_gas_price) - 1;
    let invalid_v3_tx = account_invoke_tx(invoke_tx_args! {
        // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion
        // works.
        resource_bounds: l1_resource_bounds(minimal_l1_gas.try_into().expect("Failed to convert u128 to u64."), insufficient_max_l1_gas_price),
        version: TransactionVersion::THREE,
        ..valid_invoke_tx_args
    });
    let execution_error =
        invalid_v3_tx.execute(state, block_context, true, true, None).unwrap_err();
    assert_matches!(
        execution_error,
        TransactionExecutionError::TransactionPreValidationError(
            TransactionPreValidationError::TransactionFeeError(
                TransactionFeeError::MaxL1GasPriceTooLow{ max_l1_gas_price, actual_l1_gas_price }))
        if max_l1_gas_price == insufficient_max_l1_gas_price &&
        actual_l1_gas_price == actual_strk_l1_gas_price.into()
    );
}

// TODO(Aner, 21/01/24) modify test for 4844.
#[rstest]
fn test_actual_fee_gt_resource_bounds(
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] account_cairo_version: CairoVersion,
) {
    let block_context = &block_context;
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let state = &mut test_state(
        &block_context.chain_info,
        BALANCE,
        &[(account_contract, 1), (test_contract, 1)],
    );
    let invoke_tx_args = invoke_tx_args! {
        sender_address: account_contract.get_instance_address(0),
        calldata: create_trivial_calldata(test_contract.get_instance_address(0)),
        max_fee: Fee(MAX_FEE)
    };
    let tx = &account_invoke_tx(invoke_tx_args.clone());
    let minimal_l1_gas = estimate_minimal_gas_vector(block_context, tx).unwrap().l1_gas;
    let minimal_fee =
        Fee(minimal_l1_gas * u128::from(block_context.block_info.gas_prices.eth_l1_gas_price));
    // The estimated minimal fee is lower than the actual fee.
    let invalid_tx = account_invoke_tx(invoke_tx_args! { max_fee: minimal_fee, ..invoke_tx_args });

    let execution_result = invalid_tx.execute(state, block_context, true, true, None).unwrap();
    let execution_error = execution_result.revert_error.unwrap();
    // Test error.
    assert!(execution_error.starts_with("Insufficient max fee:"));
    // Test that fee was charged.
    assert_eq!(execution_result.actual_fee, minimal_fee);
}

#[rstest]
fn test_invalid_nonce(
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] account_cairo_version: CairoVersion,
) {
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let state = &mut test_state(
        &block_context.chain_info,
        BALANCE,
        &[(account_contract, 1), (test_contract, 1)],
    );
    let valid_invoke_tx_args = invoke_tx_args! {
        sender_address: account_contract.get_instance_address(0),
        calldata: create_trivial_calldata(test_contract.get_instance_address(0)),
        max_fee: Fee(MAX_FEE)
    };
    let mut transactional_state = CachedState::create_transactional(state);

    // Strict, negative flow: account nonce = 0, incoming tx nonce = 1.
    let invalid_nonce = nonce!(1_u8);
    let invalid_tx =
        account_invoke_tx(invoke_tx_args! { nonce: invalid_nonce, ..valid_invoke_tx_args.clone() });
    let invalid_tx_context = block_context.to_tx_context(&invalid_tx);
    let pre_validation_err = invalid_tx
        .perform_pre_validation_stage(&mut transactional_state, &invalid_tx_context, false, true)
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
    let valid_nonce = nonce!(1_u8);
    let valid_tx =
        account_invoke_tx(invoke_tx_args! { nonce: valid_nonce, ..valid_invoke_tx_args.clone() });

    let valid_tx_context = block_context.to_tx_context(&valid_tx);
    valid_tx
        .perform_pre_validation_stage(&mut transactional_state, &valid_tx_context, false, false)
        .unwrap();

    // Negative flow: account nonce = 1, incoming tx nonce = 0.
    let invalid_nonce = nonce!(0_u8);
    let invalid_tx =
        account_invoke_tx(invoke_tx_args! { nonce: invalid_nonce, ..valid_invoke_tx_args.clone() });
    let invalid_tx_context = block_context.to_tx_context(&invalid_tx);
    let pre_validation_err = invalid_tx
        .perform_pre_validation_stage(&mut transactional_state, &invalid_tx_context, false, false)
        .unwrap_err();

    // Test error.
    assert_matches!(
        pre_validation_err,
        TransactionPreValidationError::InvalidNonce {address, account_nonce, incoming_tx_nonce}
        if (address, account_nonce, incoming_tx_nonce) ==
        (valid_invoke_tx_args.sender_address, nonce!(1_u8), invalid_nonce)
    );
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

/// Returns the expected used L1 gas and blob gas (according to use_kzg_da flag) due to execution of
/// a declare transaction.
fn declare_expected_state_changes_count(version: TransactionVersion) -> StateChangesCount {
    match version {
        TransactionVersion::ZERO => StateChangesCount {
            n_storage_updates: 1, // Sender balance.
            ..StateChangesCount::default()
        },
        TransactionVersion::ONE => StateChangesCount {
            n_storage_updates: 1,    // Sender balance.
            n_modified_contracts: 1, // Nonce.
            ..StateChangesCount::default()
        },
        TransactionVersion::TWO | TransactionVersion::THREE => StateChangesCount {
            n_storage_updates: 1,             // Sender balance.
            n_modified_contracts: 1,          // Nonce.
            n_compiled_class_hash_updates: 1, // Also set compiled class hash.
            ..StateChangesCount::default()
        },
        version => panic!("Unsupported version {version:?}."),
    }
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
    #[values(false, true)] use_kzg_da: bool,
) {
    let block_context = &BlockContext::create_for_account_testing_with_kzg(use_kzg_da);
    let versioned_constants = &block_context.versioned_constants;
    let empty_contract = FeatureContract::Empty(empty_contract_version);
    let account = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let chain_info = &block_context.chain_info;
    let state = &mut test_state(chain_info, BALANCE, &[(account, 1)]);
    let class_hash = empty_contract.get_class_hash();
    let class_info = calculate_class_info_for_testing(empty_contract.get_class());
    let sender_address = account.get_instance_address(0);
    let starknet_resources = StarknetResources::new(
        0,
        0,
        class_info.code_size(),
        declare_expected_state_changes_count(tx_version),
        None,
        std::iter::empty(),
    );

    let account_tx = declare_tx(
        declare_tx_args! {
            max_fee: Fee(MAX_FEE),
            sender_address,
            version: tx_version,
            resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
            class_hash,
        },
        class_info.clone(),
    );

    // Check state before transaction application.
    assert_matches!(
        state.get_compiled_contract_class(class_hash).unwrap_err(),
        StateError::UndeclaredClassHash(undeclared_class_hash) if
        undeclared_class_hash == class_hash
    );
    let fee_type = &account_tx.fee_type();
    let tx_context = &block_context.to_tx_context(&account_tx);
    let actual_execution_info = account_tx.execute(state, block_context, true, true, None).unwrap();

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
        tx_context,
        sender_address,
        expected_actual_fee,
        FeatureContract::ERC20.get_class_hash(),
    );

    let da_gas = starknet_resources.get_state_changes_cost(use_kzg_da);
    let expected_cairo_resources = get_expected_cairo_resources(
        versioned_constants,
        TransactionType::Declare,
        &starknet_resources,
        vec![&expected_validate_call_info],
    );
    let state_changes_count = starknet_resources.state_changes_for_fee;
    let expected_actual_resources = TransactionResources {
        starknet_resources,
        vm_resources: expected_cairo_resources,
        ..Default::default()
    };
    let mut expected_execution_info = TransactionExecutionInfo {
        validate_call_info: expected_validate_call_info,
        execute_call_info: None,
        fee_transfer_call_info: expected_fee_transfer_call_info,
        actual_fee: expected_actual_fee,
        da_gas,
        revert_error: None,
        actual_resources: expected_actual_resources,
    };

    add_kzg_da_resources_to_resources_mapping(
        &mut expected_execution_info.actual_resources.vm_resources,
        &state_changes_count,
        versioned_constants,
        use_kzg_da,
    );

    // Test execution info result.
    assert_eq!(actual_execution_info, expected_execution_info);

    // Test nonce update. V0 transactions do not update nonce.
    let expected_nonce = nonce!(if tx_version == TransactionVersion::ZERO { 0_u8 } else { 1_u8 });
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
    assert_eq!(contract_class_from_state, class_info.contract_class());
}

#[rstest]
fn test_deploy_account_tx(
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
    #[values(false, true)] use_kzg_da: bool,
) {
    let block_context = &BlockContext::create_for_account_testing_with_kzg(use_kzg_da);
    let versioned_constants = &block_context.versioned_constants;
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
                stark_felt!(BALANCE),
            )
            .unwrap();
    }

    let account_tx = AccountTransaction::DeployAccount(deploy_account);
    let fee_type = &account_tx.fee_type();
    let tx_context = &block_context.to_tx_context(&account_tx);
    let actual_execution_info = account_tx.execute(state, block_context, true, true, None).unwrap();

    // Build expected validate call info.
    let validate_calldata =
        [vec![class_hash.0, salt.0], (*constructor_calldata.0).clone()].concat();
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
            initial_gas: tx_initial_gas(),
            ..Default::default()
        },
        ..Default::default()
    });

    // Build expected fee transfer call info.
    let expected_actual_fee =
        calculate_tx_fee(&actual_execution_info.actual_resources.clone(), block_context, fee_type)
            .unwrap();
    let expected_fee_transfer_call_info = expected_fee_transfer_call_info(
        tx_context,
        deployed_account_address,
        expected_actual_fee,
        FeatureContract::ERC20.get_class_hash(),
    );
    let starknet_resources = actual_execution_info.actual_resources.starknet_resources.clone();

    let state_changes_count = StateChangesCount {
        n_storage_updates: 1,
        n_modified_contracts: 1,
        n_class_hash_updates: 1,
        ..StateChangesCount::default()
    };
    let da_gas = get_da_gas_cost(&state_changes_count, use_kzg_da);
    let expected_cairo_resources = get_expected_cairo_resources(
        &block_context.versioned_constants,
        TransactionType::DeployAccount,
        &starknet_resources,
        vec![&expected_validate_call_info, &expected_execute_call_info],
    );

    let actual_resources = TransactionResources {
        starknet_resources,
        vm_resources: expected_cairo_resources,
        ..Default::default()
    };
    let mut expected_execution_info = TransactionExecutionInfo {
        validate_call_info: expected_validate_call_info,
        execute_call_info: expected_execute_call_info,
        fee_transfer_call_info: expected_fee_transfer_call_info,
        actual_fee: expected_actual_fee,
        da_gas,
        revert_error: None,
        actual_resources,
    };

    add_kzg_da_resources_to_resources_mapping(
        &mut expected_execution_info.actual_resources.vm_resources,
        &state_changes_count,
        versioned_constants,
        use_kzg_da,
    );

    // Test execution info result.
    assert_eq!(actual_execution_info, expected_execution_info);

    // Test nonce update.
    let nonce_from_state = state.get_nonce_at(deployed_account_address).unwrap();
    assert_eq!(nonce_from_state, nonce!(1_u8));

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
    let error = account_tx.execute(state, block_context, true, true, None).unwrap_err();
    assert_matches!(
        error,
        TransactionExecutionError::ContractConstructorExecutionFailed(
            ConstructorEntryPointExecutionError::ExecutionError {
                error: EntryPointExecutionError::StateError(
                    StateError::UnavailableContractAddress(_)
                ),
                ..
            }
        )
    );
}

#[rstest]
fn test_fail_deploy_account_undeclared_class_hash(block_context: BlockContext) {
    let block_context = &block_context;
    let chain_info = &block_context.chain_info;
    let state = &mut test_state(chain_info, BALANCE, &[]);
    let mut nonce_manager = NonceManager::default();
    let undeclared_hash = class_hash!("0xdeadbeef");
    let deploy_account = deploy_account_tx(
        deploy_account_tx_args! { max_fee: Fee(MAX_FEE), class_hash: undeclared_hash },
        &mut nonce_manager,
    );

    // Fund account, so as not to fail pre-validation.
    state
        .set_storage_at(
            chain_info.fee_token_address(&FeeType::Eth),
            get_fee_token_var_address(deploy_account.contract_address),
            stark_felt!(BALANCE),
        )
        .unwrap();

    let account_tx = AccountTransaction::DeployAccount(deploy_account);
    let error = account_tx.execute(state, block_context, true, true, None).unwrap_err();
    assert_matches!(
        error,
        TransactionExecutionError::ContractConstructorExecutionFailed(
            ConstructorEntryPointExecutionError::ExecutionError {
                error: EntryPointExecutionError::StateError(
                    StateError::UndeclaredClassHash(class_hash)
                ),
                ..
            }
        )
        if class_hash == undeclared_hash
    );
}

// TODO(Arni, 1/5/2024): Cover other versions of declare transaction.
// TODO(Arni, 1/5/2024): Consider version 0 invoke.
#[rstest]
#[case::validate_version_1(TransactionType::InvokeFunction, false, TransactionVersion::ONE)]
#[case::validate_version_3(TransactionType::InvokeFunction, false, TransactionVersion::THREE)]
#[case::validate_declare_version_1(TransactionType::Declare, false, TransactionVersion::ONE)]
#[case::validate_declare_version_2(TransactionType::Declare, false, TransactionVersion::TWO)]
#[case::validate_declare_version_3(TransactionType::Declare, false, TransactionVersion::THREE)]
#[case::validate_deploy_version_1(TransactionType::DeployAccount, false, TransactionVersion::ONE)]
#[case::validate_deploy_version_3(TransactionType::DeployAccount, false, TransactionVersion::THREE)]
#[case::constructor_version_1(TransactionType::DeployAccount, true, TransactionVersion::ONE)]
#[case::constructor_version_3(TransactionType::DeployAccount, true, TransactionVersion::THREE)]
fn test_validate_accounts_tx(
    block_context: BlockContext,
    #[case] tx_type: TransactionType,
    #[case] validate_constructor: bool,
    #[case] tx_version: TransactionVersion,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let block_context = &block_context;
    let account_balance = 0;
    let faulty_account = FeatureContract::FaultyAccount(cairo_version);
    let sender_address = faulty_account.get_instance_address(0);
    let class_hash = faulty_account.get_class_hash();
    let state = &mut test_state(&block_context.chain_info, account_balance, &[(faulty_account, 1)]);
    let salt_manager = &mut SaltManager::default();

    let default_args = FaultyAccountTxCreatorArgs {
        tx_type,
        tx_version,
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
            additional_data: None,
            ..default_args
        },
    );
    let error = account_tx.execute(state, block_context, true, true, None).unwrap_err();
    check_transaction_execution_error_for_invalid_scenario!(
        cairo_version,
        error,
        validate_constructor,
    );

    // Try to call another contract (forbidden).
    let account_tx = create_account_tx_for_validate_test(
        &mut NonceManager::default(),
        FaultyAccountTxCreatorArgs {
            scenario: CALL_CONTRACT,
            additional_data: Some(vec![stark_felt!("0x1991")]), /* Some address different than
                                                                 * the address of
                                                                 * faulty_account. */
            contract_address_salt: salt_manager.next_salt(),
            ..default_args
        },
    );
    let error = account_tx.execute(state, block_context, true, true, None).unwrap_err();
    check_transaction_execution_error_for_custom_hint!(
        &error,
        "Unauthorized syscall call_contract in execution mode Validate.",
        validate_constructor,
    );

    if let CairoVersion::Cairo1 = cairo_version {
        // Try to use the syscall get_block_hash (forbidden).
        let account_tx = create_account_tx_for_validate_test(
            &mut NonceManager::default(),
            FaultyAccountTxCreatorArgs {
                scenario: GET_BLOCK_HASH,
                contract_address_salt: salt_manager.next_salt(),
                additional_data: None,
                ..default_args
            },
        );
        let error = account_tx.execute(state, block_context, true, true, None).unwrap_err();
        check_transaction_execution_error_for_custom_hint!(
            &error,
            "Unauthorized syscall get_block_hash in execution mode Validate.",
            validate_constructor,
        );
    }
    if let CairoVersion::Cairo0 = cairo_version {
        // Try to use the syscall get_sequencer_address (forbidden).
        let account_tx = create_account_tx_for_validate_test(
            &mut NonceManager::default(),
            FaultyAccountTxCreatorArgs {
                scenario: GET_SEQUENCER_ADDRESS,
                contract_address_salt: salt_manager.next_salt(),
                ..default_args
            },
        );
        let error = account_tx.execute(state, block_context, true, true, None).unwrap_err();
        check_transaction_execution_error_for_custom_hint!(
            &error,
            "Unauthorized syscall get_sequencer_address in execution mode Validate.",
            validate_constructor,
        );
    }

    // Positive flows.

    // Valid logic.
    let nonce_manager = &mut NonceManager::default();
    let declared_contract_cairo_version = CairoVersion::from_declare_tx_version(tx_version);
    let account_tx = create_account_tx_for_validate_test(
        nonce_manager,
        FaultyAccountTxCreatorArgs {
            scenario: VALID,
            contract_address_salt: salt_manager.next_salt(),
            additional_data: None,
            declared_contract: Some(FeatureContract::TestContract(declared_contract_cairo_version)),
            ..default_args
        },
    );
    let result = account_tx.execute(state, block_context, true, true, None);
    assert!(result.is_ok(), "Execution failed: {:?}", result.unwrap_err());

    if tx_type != TransactionType::DeployAccount {
        // Call self (allowed).
        let account_tx = create_account_tx_for_validate_test(
            nonce_manager,
            FaultyAccountTxCreatorArgs {
                scenario: CALL_CONTRACT,
                additional_data: Some(vec![*sender_address.0.key()]),
                declared_contract: Some(FeatureContract::AccountWithLongValidate(
                    declared_contract_cairo_version,
                )),
                ..default_args
            },
        );
        let result = account_tx.execute(state, block_context, true, true, None);
        assert!(result.is_ok(), "Execution failed: {:?}", result.unwrap_err());
    }

    if let CairoVersion::Cairo0 = cairo_version {
        // Call the syscall get_block_number and assert the returned block number was modified
        // for validate.
        let account_tx = create_account_tx_for_validate_test(
            nonce_manager,
            FaultyAccountTxCreatorArgs {
                scenario: GET_BLOCK_NUMBER,
                contract_address_salt: salt_manager.next_salt(),
                additional_data: Some(vec![StarkFelt::from(CURRENT_BLOCK_NUMBER_FOR_VALIDATE)]),
                declared_contract: Some(FeatureContract::AccountWithoutValidations(
                    declared_contract_cairo_version,
                )),
                ..default_args
            },
        );
        let result = account_tx.execute(state, block_context, true, true, None);
        assert!(result.is_ok(), "Execution failed: {:?}", result.unwrap_err());

        // Call the syscall get_block_timestamp and assert the returned timestamp was modified
        // for validate.
        let account_tx = create_account_tx_for_validate_test(
            nonce_manager,
            FaultyAccountTxCreatorArgs {
                scenario: GET_BLOCK_TIMESTAMP,
                contract_address_salt: salt_manager.next_salt(),
                additional_data: Some(vec![StarkFelt::from(CURRENT_BLOCK_TIMESTAMP_FOR_VALIDATE)]),
                declared_contract: Some(FeatureContract::Empty(declared_contract_cairo_version)),
                ..default_args
            },
        );
        let result = account_tx.execute(state, block_context, true, true, None);
        assert!(result.is_ok(), "Execution failed: {:?}", result.unwrap_err());
    }

    if let CairoVersion::Cairo1 = cairo_version {
        let account_tx = create_account_tx_for_validate_test(
            // Call the syscall get_execution_info and assert the returned block_info was
            // modified for validate.
            nonce_manager,
            FaultyAccountTxCreatorArgs {
                scenario: GET_EXECUTION_INFO,
                contract_address_salt: salt_manager.next_salt(),
                additional_data: Some(vec![
                    StarkFelt::from(CURRENT_BLOCK_NUMBER_FOR_VALIDATE),
                    StarkFelt::from(CURRENT_BLOCK_TIMESTAMP_FOR_VALIDATE),
                    StarkFelt::from(0_u64), // Sequencer address for validate.
                ]),
                declared_contract: Some(FeatureContract::Empty(declared_contract_cairo_version)),
                ..default_args
            },
        );
        let result = account_tx.execute(state, block_context, true, true, None);
        assert!(result.is_ok(), "Execution failed: {:?}", result.unwrap_err());
    }
}

#[rstest]
fn test_valid_flag(
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] account_cairo_version: CairoVersion,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] test_contract_cairo_version: CairoVersion,
) {
    let block_context = &block_context;
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(test_contract_cairo_version);
    let state = &mut test_state(
        &block_context.chain_info,
        BALANCE,
        &[(account_contract, 1), (test_contract, 1)],
    );

    let account_tx = account_invoke_tx(invoke_tx_args! {
        sender_address: account_contract.get_instance_address(0),
        calldata: create_trivial_calldata(test_contract.get_instance_address(0)),
        max_fee: Fee(MAX_FEE)
    });

    let actual_execution_info =
        account_tx.execute(state, block_context, true, false, None).unwrap();

    assert!(actual_execution_info.validate_call_info.is_none());
}

// TODO(Noa,01/12/2023): Consider moving it to syscall_test.
#[rstest]
fn test_only_query_flag(block_context: BlockContext, #[values(true, false)] only_query: bool) {
    let account_balance = BALANCE;
    let block_context = &block_context;
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let state = &mut test_state(
        &block_context.chain_info,
        account_balance,
        &[(account, 1), (test_contract, 1)],
    );
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
        *test_contract_address.0.key(), // Contract address.
        entry_point_selector.0,         // EP selector.
        // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion
        // works.
        stark_felt!(u64::try_from(calldata_len).expect("Failed to convert usize to u64.")), /* Calldata length. */
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

    let tx_execution_info = account_tx.execute(state, block_context, true, true, None).unwrap();
    assert!(!tx_execution_info.is_reverted())
}

#[rstest]
fn test_l1_handler(#[values(false, true)] use_kzg_da: bool) {
    let cairo_version = CairoVersion::Cairo1;
    let test_contract = FeatureContract::TestContract(cairo_version);
    let chain_info = &ChainInfo::create_for_testing();
    let state = &mut test_state(chain_info, BALANCE, &[(test_contract, 1)]);
    let block_context = &BlockContext::create_for_account_testing_with_kzg(use_kzg_da);
    let contract_address = test_contract.get_instance_address(0);
    let versioned_constants = &block_context.versioned_constants;
    let tx = L1HandlerTransaction::create_for_testing(Fee(1), contract_address);
    let calldata = tx.tx.calldata.clone();
    let key = calldata.0[1];
    let value = calldata.0[2];
    let payload_size = tx.payload_size();

    let actual_execution_info = tx.execute(state, block_context, true, true, None).unwrap();

    // Build the expected call info.
    let accessed_storage_key = StorageKey::try_from(key).unwrap();
    let expected_call_info = CallInfo {
        call: CallEntryPoint {
            class_hash: Some(test_contract.get_class_hash()),
            code_address: None,
            entry_point_type: EntryPointType::L1Handler,
            entry_point_selector: selector_from_name("l1_handler_set_value"),
            calldata: calldata.clone(),
            storage_address: contract_address,
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
            initial_gas: tx_initial_gas(),
        },
        execution: CallExecution {
            retdata: Retdata(vec![value]),
            gas_consumed: 11750,
            ..Default::default()
        },
        resources: ExecutionResources {
            n_steps: 154,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 6)]),
        },
        accessed_storage_keys: HashSet::from_iter(vec![accessed_storage_key]),
        ..Default::default()
    };

    // Build the expected resource mapping.
    // TODO(Nimrod, 1/5/2024): Change these hard coded values to match to the transaction resources
    // (currently matches only starknet resources).
    let expected_gas = match use_kzg_da {
        true => GasVector { l1_gas: 16023, l1_data_gas: 128 },
        false => GasVector::from_l1_gas(17675),
    };
    let expected_da_gas = match use_kzg_da {
        true => GasVector::from_l1_data_gas(128),
        false => GasVector::from_l1_gas(1652),
    };

    let state_changes_count = StateChangesCount {
        n_storage_updates: 1,
        n_modified_contracts: 1,
        ..StateChangesCount::default()
    };

    let mut expected_execution_resources = ExecutionResources {
        builtin_instance_counter: HashMap::from([
            (HASH_BUILTIN_NAME.to_string(), 11 + payload_size),
            (
                RANGE_CHECK_BUILTIN_NAME.to_string(),
                get_tx_resources(TransactionType::L1Handler).builtin_instance_counter
                    [&RANGE_CHECK_BUILTIN_NAME.to_string()]
                    + 6,
            ),
        ]),
        n_steps: get_tx_resources(TransactionType::L1Handler).n_steps + 167,
        n_memory_holes: 0,
    };

    add_kzg_da_resources_to_resources_mapping(
        &mut expected_execution_resources,
        &state_changes_count,
        versioned_constants,
        use_kzg_da,
    );

    // Copy StarknetResources from actual resources and assert gas usage calculation is correct.
    let expected_tx_resources = TransactionResources {
        starknet_resources: actual_execution_info.actual_resources.starknet_resources.clone(),
        vm_resources: expected_execution_resources,
        ..Default::default()
    };
    assert_eq!(
        expected_gas,
        actual_execution_info
            .actual_resources
            .starknet_resources
            .to_gas_vector(versioned_constants, use_kzg_da)
    );
    // Build the expected execution info.
    let expected_execution_info = TransactionExecutionInfo {
        validate_call_info: None,
        execute_call_info: Some(expected_call_info),
        fee_transfer_call_info: None,
        actual_fee: Fee(0),
        da_gas: expected_da_gas,
        actual_resources: expected_tx_resources,
        revert_error: None,
    };

    // Check the actual returned execution info.
    assert_eq!(actual_execution_info, expected_execution_info);

    // Check the state changes.
    assert_eq!(
        state.get_storage_at(contract_address, StorageKey::try_from(key).unwrap(),).unwrap(),
        value,
    );
    // Negative flow: not enough fee paid on L1.

    // set the storage back to 0, so the fee will also include the storage write.
    // TODO(Meshi, 15/6/2024): change the l1_handler_set_value cairo function to
    // always uptade the storage instad.
    state
        .set_storage_at(
            contract_address,
            StorageKey::try_from(key).unwrap(),
            StarkFelt::from_u128(0),
        )
        .unwrap();
    let tx_no_fee = L1HandlerTransaction::create_for_testing(Fee(0), contract_address);
    let error = tx_no_fee.execute(state, block_context, true, true, None).unwrap_err();
    // Today, we check that the paid_fee is positive, no matter what was the actual fee.
    let expected_actual_fee =
        calculate_tx_fee(&expected_execution_info.actual_resources, block_context, &FeeType::Eth)
            .unwrap();
    assert_matches!(
        error,
        TransactionExecutionError::TransactionFeeError(
            TransactionFeeError::InsufficientL1Fee { paid_fee, actual_fee, })
            if paid_fee == Fee(0) && actual_fee == expected_actual_fee
    );
}

#[rstest]
fn test_execute_tx_with_invalid_transaction_version(block_context: BlockContext) {
    let cairo_version = CairoVersion::Cairo0;
    let account = FeatureContract::AccountWithoutValidations(cairo_version);
    let test_contract = FeatureContract::TestContract(cairo_version);
    let block_context = &block_context;
    let state =
        &mut test_state(&block_context.chain_info, BALANCE, &[(account, 1), (test_contract, 1)]);
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

    let execution_info = account_tx.execute(state, block_context, true, true, None).unwrap();
    assert!(
        execution_info
            .revert_error
            .unwrap()
            .contains(format!("ASSERT_EQ instruction failed: {} != 1.", invalid_version).as_str())
    );
}

fn max_n_emitted_events() -> usize {
    VERSIONED_CONSTANTS.tx_event_limits.max_n_emitted_events
}

fn max_event_keys() -> usize {
    VERSIONED_CONSTANTS.tx_event_limits.max_keys_length
}

fn max_event_data() -> usize {
    VERSIONED_CONSTANTS.tx_event_limits.max_data_length
}

#[rstest]
#[case::positive_flow(
    vec![stark_felt!(1_u16); max_event_keys()],
    vec![stark_felt!(2_u16); max_event_data()],
    max_n_emitted_events(),
    None)]
#[case::exceeds_max_number_of_events(
    vec![stark_felt!(1_u16)],
    vec![stark_felt!(2_u16)],
    max_n_emitted_events() + 1,
    Some(EmitEventError::ExceedsMaxNumberOfEmittedEvents {
        n_emitted_events: max_n_emitted_events() + 1,
        max_n_emitted_events: max_n_emitted_events(),
    }))]
#[case::exceeds_max_number_of_keys(
    vec![stark_felt!(3_u16); max_event_keys() + 1],
    vec![stark_felt!(4_u16)],
    1,
    Some(EmitEventError::ExceedsMaxKeysLength{
        keys_length: max_event_keys() + 1,
        max_keys_length: max_event_keys(),
    }))]
#[case::exceeds_data_length(
    vec![stark_felt!(5_u16)],
    vec![stark_felt!(6_u16); max_event_data() + 1],
    1,
    Some(EmitEventError::ExceedsMaxDataLength{
        data_length: max_event_data() + 1,
        max_data_length: max_event_data(),
    }))]
fn test_emit_event_exceeds_limit(
    block_context: BlockContext,
    #[case] event_keys: Vec<StarkFelt>,
    #[case] event_data: Vec<StarkFelt>,
    #[case] n_emitted_events: usize,
    #[case] expected_error: Option<EmitEventError>,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let test_contract = FeatureContract::TestContract(cairo_version);
    let account_contract = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let block_context = &block_context;
    let state = &mut test_state(
        &block_context.chain_info,
        BALANCE,
        &[(test_contract, 1), (account_contract, 1)],
    );

    let calldata = [
        vec![stark_felt!(
            u16::try_from(n_emitted_events).expect("Failed to convert usize to u16.")
        )]
        .to_owned(),
        vec![stark_felt!(
            u16::try_from(event_keys.len()).expect("Failed to convert usize to u16.")
        )],
        event_keys.clone(),
        vec![stark_felt!(
            u16::try_from(event_data.len()).expect("Failed to convert usize to u16.")
        )],
        event_data.clone(),
    ]
    .concat();
    let execute_calldata = Calldata(
        [
            vec![test_contract.get_instance_address(0).into()],
            vec![selector_from_name("test_emit_events").0],
            vec![stark_felt!(
                u16::try_from(calldata.len()).expect("Failed to convert usize to u16.")
            )],
            calldata.clone(),
        ]
        .concat()
        .into(),
    );

    let account_tx = account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(MAX_FEE),
        sender_address: account_contract.get_instance_address(0),
        calldata: execute_calldata,
        version: TransactionVersion::ONE,
        nonce: nonce!(0_u8),
    });
    let execution_info = account_tx.execute(state, block_context, true, true, None).unwrap();
    match &expected_error {
        Some(expected_error) => {
            let error_string = execution_info.revert_error.unwrap();
            assert!(error_string.contains(&format!("{}", expected_error)));
        }
        None => {
            assert!(!execution_info.is_reverted());
        }
    }
}
