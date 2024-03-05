use std::collections::HashMap;

use cairo_vm::vm::runners::builtin_runner::{
    BITWISE_BUILTIN_NAME, EC_OP_BUILTIN_NAME, HASH_BUILTIN_NAME, KECCAK_BUILTIN_NAME,
    OUTPUT_BUILTIN_NAME, POSEIDON_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME, SIGNATURE_BUILTIN_NAME,
};
use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, Fee, TransactionHash, TransactionVersion};
use starknet_api::{calldata, stark_felt};

use crate::abi::abi_utils::selector_from_name;
use crate::blockifier::bouncer::BouncerInfo;
use crate::blockifier::transaction_executor::TransactionExecutor;
use crate::context::BlockContext;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::declare::declare_tx;
use crate::test_utils::deploy_account::deploy_account_tx;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{CairoVersion, NonceManager, BALANCE, DEFAULT_STRK_L1_GAS_PRICE};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::test_utils::{
    account_invoke_tx, block_context, calculate_class_info_for_testing, l1_resource_bounds,
};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transactions::L1HandlerTransaction;
use crate::{declare_tx_args, deploy_account_tx_args, invoke_tx_args};

// Utils.

/// Creates a builtin instance counter for testing. The counter is initialized with the default
/// value 0 for each builtin, and then the provided builtin_instance_counter is added to it.
fn build_expected_builtin_instance_counter(
    builtin_instance_counter: HashMap<String, usize>,
) -> HashMap<String, usize> {
    let mut expected_builtin_instance_counter = HashMap::from([
        (HASH_BUILTIN_NAME.to_string(), 0),
        (RANGE_CHECK_BUILTIN_NAME.to_string(), 0),
        (BITWISE_BUILTIN_NAME.to_string(), 0),
        (SIGNATURE_BUILTIN_NAME.to_string(), 0),
        (POSEIDON_BUILTIN_NAME.to_string(), 0),
        (EC_OP_BUILTIN_NAME.to_string(), 0),
        (KECCAK_BUILTIN_NAME.to_string(), 0),
        (OUTPUT_BUILTIN_NAME.to_string(), 0),
    ]);
    expected_builtin_instance_counter.extend(builtin_instance_counter);
    expected_builtin_instance_counter
}

fn declare_tx_for_test(
    account_address: ContractAddress,
    declared_contract: FeatureContract,
    version: TransactionVersion,
) -> Transaction {
    let zero_bounds = true;
    Transaction::AccountTransaction(declare_tx(
        declare_tx_args! {
            sender_address: account_address,
            class_hash: declared_contract.get_class_hash(),
            version,
            max_fee: Fee(u128::from(!zero_bounds)),
            resource_bounds: l1_resource_bounds(u64::from(!zero_bounds), DEFAULT_STRK_L1_GAS_PRICE),
        },
        calculate_class_info_for_testing(declared_contract.get_class()),
    ))
}

fn invoke_function_tx_for_test(
    account_address: ContractAddress,
    contract_address: ContractAddress,
    version: TransactionVersion,
) -> Transaction {
    let zero_bounds = true;
    Transaction::AccountTransaction(account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(u128::from(!zero_bounds)),
        sender_address: account_address,
        calldata: calldata![
            contract_address.into(), // Contract address.
            selector_from_name("assert_eq").0,    // EP selector.
            stark_felt!(2_u8),         // Calldata length.
            stark_felt!(3_u8),          // Calldata: x.
            stark_felt!(3_u8)          // Calldata: y.
        ],
        version,
    }))
}

fn deploy_account_tx_for_test(class_hash: ClassHash, version: TransactionVersion) -> Transaction {
    let zero_bounds = true;
    Transaction::AccountTransaction(AccountTransaction::DeployAccount(deploy_account_tx(
        deploy_account_tx_args! {
            class_hash,
            max_fee: Fee(u128::from(!zero_bounds)),
            resource_bounds: l1_resource_bounds(u64::from(!zero_bounds), DEFAULT_STRK_L1_GAS_PRICE),
            version,
        },
        &mut NonceManager::default(),
    )))
}

fn l1_handler_for_test(
    contract_address: ContractAddress,
    version: TransactionVersion,
) -> Transaction {
    let calldata = starknet_api::calldata![
        StarkFelt::from_u128(0x123), // from_address.
        StarkFelt::from_u128(0x876), // key.
        StarkFelt::from_u128(0x44)   // value.
    ];
    Transaction::L1HandlerTransaction(L1HandlerTransaction {
        tx: starknet_api::transaction::L1HandlerTransaction {
            version,
            nonce: Nonce::default(),
            contract_address,
            entry_point_selector: selector_from_name("l1_handler_set_value"),
            calldata,
        },
        tx_hash: TransactionHash::default(),
        paid_fee_on_l1: Fee(1908000000000000),
    })
}

#[rstest]
#[case::declare_tx(TransactionType::Declare, TransactionVersion::THREE, BouncerInfo {
    state_diff_size: 4,
    gas_weight: 0,
    message_segment_length: 0,
    execution_resources: cairo_vm::vm::runners::cairo_runner::ExecutionResources {
        n_steps: 4595,
        n_memory_holes: 0,
        builtin_instance_counter: build_expected_builtin_instance_counter(HashMap::from([
            (HASH_BUILTIN_NAME.to_string(), 234),
            (RANGE_CHECK_BUILTIN_NAME.to_string(), 63),
        ])),
    },
    n_events: 0,
})]
#[case::invoke_function(TransactionType::InvokeFunction, TransactionVersion::THREE, BouncerInfo {
    state_diff_size: 2,
    gas_weight: 0,
    message_segment_length: 0,
    execution_resources: cairo_vm::vm::runners::cairo_runner::ExecutionResources {
        n_steps: 91483,
        n_memory_holes: 0,
        builtin_instance_counter: build_expected_builtin_instance_counter(HashMap::from([
            (HASH_BUILTIN_NAME.to_string(), 237),
            (RANGE_CHECK_BUILTIN_NAME.to_string(), 104),
            (POSEIDON_BUILTIN_NAME.to_string(), 7716),
        ])),
    },
    n_events: 0,
})]
#[case::deploy_account_tx(TransactionType::DeployAccount, TransactionVersion::THREE, BouncerInfo {
    state_diff_size: 3,
    gas_weight: 0,
    message_segment_length: 0,
    execution_resources: cairo_vm::vm::runners::cairo_runner::ExecutionResources {
        n_steps: 5549,
        n_memory_holes: 0,
        builtin_instance_counter: build_expected_builtin_instance_counter(HashMap::from([
            (HASH_BUILTIN_NAME.to_string(), 241),
            (RANGE_CHECK_BUILTIN_NAME.to_string(), 83),
        ])),
    },
    n_events: 0,
})]
#[case::l1_handler(TransactionType::L1Handler, TransactionVersion::ZERO, BouncerInfo {
    state_diff_size: 4,
    gas_weight: 11739,
    message_segment_length: 7,
    execution_resources: cairo_vm::vm::runners::cairo_runner::ExecutionResources {
        n_steps: 87423,
        n_memory_holes: 0,
        builtin_instance_counter: build_expected_builtin_instance_counter(HashMap::from([
            (HASH_BUILTIN_NAME.to_string(), 61),
            (POSEIDON_BUILTIN_NAME.to_string(), 7716),
            (RANGE_CHECK_BUILTIN_NAME.to_string(), 23),
        ])),
    },
    n_events: 0,
})]
/// Test the execute function of the TransactionExecutor.
fn test_tx_executor(
    block_context: BlockContext,
    // TODO: consider TransactionVersion::ONE.
    #[case] tx_type: TransactionType,
    #[case] version: TransactionVersion,
    #[case] expected_bouncer_info: BouncerInfo,
    #[values(true)] charge_fee: bool,
) {
    // constants for the test.

    // Setup context.
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo0);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let empty = FeatureContract::Empty(CairoVersion::Cairo1); // Some unused contract.
    let state = test_state(&block_context.chain_info, BALANCE, &[(account, 1), (test_contract, 1)]);

    // Create the tx executor.
    let mut tx_executor = TransactionExecutor::new(state, block_context);

    // Create the tested tx.
    let tx = match tx_type {
        TransactionType::Declare => {
            declare_tx_for_test(account.get_instance_address(0), empty, version)
        }
        TransactionType::DeployAccount => {
            deploy_account_tx_for_test(account.get_class_hash(), version)
        }
        TransactionType::InvokeFunction => invoke_function_tx_for_test(
            account.get_instance_address(0),
            test_contract.get_instance_address(0),
            version,
        ),
        TransactionType::L1Handler => {
            l1_handler_for_test(test_contract.get_instance_address(0), version)
        }
    };

    let (_tx_execution_info, bouncer_info) = tx_executor.execute(tx, charge_fee).unwrap();

    assert_eq!(bouncer_info, expected_bouncer_info);
}
