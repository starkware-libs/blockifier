use std::collections::HashMap;

use num_bigint::BigUint;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{ContractAddressSalt, Fee, TransactionVersion};
use starknet_api::{contract_address, patricia_key, stark_felt};

use super::WorkerExecutor;
use crate::abi::abi_utils::get_fee_token_var_address;
use crate::abi::sierra_types::next_storage_key;
use crate::concurrency::scheduler::{Task, TransactionStatus};
use crate::concurrency::test_utils::safe_versioned_state_for_testing;
use crate::concurrency::worker_logic::add_fee_to_sequencer_balance;
use crate::context::BlockContext;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::state::cached_state::StateMaps;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::declare::declare_tx;
use crate::test_utils::initial_test_state::test_state_reader;
use crate::test_utils::{
    create_calldata, CairoVersion, NonceManager, BALANCE, MAX_FEE, MAX_L1_GAS_AMOUNT,
    MAX_L1_GAS_PRICE, TEST_ERC20_CONTRACT_ADDRESS,
};
use crate::transaction::constants::DEPLOY_CONTRACT_FUNCTION_ENTRY_POINT_NAME;
use crate::transaction::objects::FeeType;
use crate::transaction::test_utils::{
    account_invoke_tx, calculate_class_info_for_testing, l1_resource_bounds,
};
use crate::transaction::transaction_execution::Transaction;
use crate::{declare_tx_args, invoke_tx_args, nonce, storage_key};

#[test]
fn test_worker_execute() {
    // Settings.
    let concurrency_mode = true;
    let block_context =
        BlockContext::create_for_account_testing_with_concurrency_mode(concurrency_mode);
    let account_contract = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let chain_info = &block_context.chain_info;

    // Create the state.
    let state_reader =
        test_state_reader(chain_info, BALANCE, &[(account_contract, 1), (test_contract, 1)]);
    let safe_versioned_state = safe_versioned_state_for_testing(state_reader);

    // Create transactions.
    let test_contract_address = test_contract.get_instance_address(0);
    let account_address = account_contract.get_instance_address(0);
    let nonce_manager = &mut NonceManager::default();
    let storage_value = stark_felt!(93_u8);
    let storage_key = storage_key!(1993_u16);

    let tx_success = account_invoke_tx(invoke_tx_args! {
        sender_address: account_address,
        calldata: create_calldata(
            test_contract_address,
            "test_storage_read_write",
            &[*storage_key.0.key(),storage_value ], // Calldata:  address, value.
        ),
        max_fee: Fee(MAX_FEE),
        nonce: nonce_manager.next(account_address)
    });

    // Create a transaction with invalid nonce.
    nonce_manager.rollback(account_address);
    let tx_failure = account_invoke_tx(invoke_tx_args! {
        sender_address: account_address,
        calldata: create_calldata(
            test_contract_address,
            "test_storage_read_write",
            &[*storage_key.0.key(),storage_value ], // Calldata:  address, value.
        ),
        max_fee: Fee(MAX_FEE),
        nonce: nonce_manager.next(account_address)

    });

    let tx_revert = account_invoke_tx(invoke_tx_args! {
        sender_address: account_address,
        calldata: create_calldata(
            test_contract_address,
            "write_and_revert",
            &[stark_felt!(1991_u16),storage_value ], // Calldata:  address, value.
        ),
        max_fee: Fee(MAX_FEE),
        nonce: nonce_manager.next(account_address)

    });

    // Concurrency settings.
    let txs = [tx_success, tx_failure, tx_revert]
        .into_iter()
        .map(Transaction::AccountTransaction)
        .collect::<Vec<Transaction>>();

    let worker_executor = WorkerExecutor::new(safe_versioned_state.clone(), &txs, block_context);

    // Creates 3 execution active tasks.
    worker_executor.scheduler.next_task();
    worker_executor.scheduler.next_task();
    worker_executor.scheduler.next_task();

    // Successful execution.
    let tx_index = 0;
    worker_executor.execute(tx_index);
    // Read a write made by the transaction.
    assert_eq!(
        safe_versioned_state
            .pin_version(tx_index)
            .get_storage_at(test_contract_address, storage_key)
            .unwrap(),
        storage_value
    );
    // Verify the output was written. Validate its correctness.
    let execution_output = worker_executor.execution_outputs[tx_index].lock().unwrap();
    let execution_output = execution_output.as_ref().unwrap();
    let result = execution_output.result.as_ref().unwrap();
    let account_balance = BALANCE - result.actual_fee.0;
    assert!(!result.is_reverted());

    let erc20 = FeatureContract::ERC20;
    let erc_contract_address = contract_address!(TEST_ERC20_CONTRACT_ADDRESS);
    let account_balance_key_low = get_fee_token_var_address(account_address);
    let account_balance_key_high = next_storage_key(&account_balance_key_low).unwrap();
    // Both in write and read sets, only the account balance appear, and not the sequencer balance.
    // This is because when executing transaction in concurrency mode on, we manually remove the
    // writes and reads to and from the sequencer balance (to avoid the inevitable dependency
    // between all the transactions).
    let writes = StateMaps {
        nonces: HashMap::from([(account_address, nonce!(1_u8))]),
        storage: HashMap::from([
            ((test_contract_address, storage_key), storage_value),
            ((erc_contract_address, account_balance_key_low), stark_felt!(account_balance)),
            ((erc_contract_address, account_balance_key_high), stark_felt!(0_u8)),
        ]),
        ..Default::default()
    };
    let reads = StateMaps {
        nonces: HashMap::from([(account_address, nonce!(0_u8))]),
        // Before running an entry point (call contract), we verify the contract is deployed.
        class_hashes: HashMap::from([
            (account_address, account_contract.get_class_hash()),
            (test_contract_address, test_contract.get_class_hash()),
            (erc_contract_address, erc20.get_class_hash()),
        ]),
        storage: HashMap::from([
            ((test_contract_address, storage_key), stark_felt!(0_u8)),
            ((erc_contract_address, account_balance_key_low), stark_felt!(BALANCE)),
            ((erc_contract_address, account_balance_key_high), stark_felt!(0_u8)),
        ]),
        // When running an entry point, we load its contract class.
        declared_contracts: HashMap::from([
            (account_contract.get_class_hash(), true),
            (test_contract.get_class_hash(), true),
            (erc20.get_class_hash(), true),
        ]),
        ..Default::default()
    };

    assert_eq!(execution_output.writes, writes);
    assert_eq!(execution_output.reads, reads);
    assert_ne!(execution_output.visited_pcs, HashMap::default());

    // Failed execution.
    let tx_index = 1;
    worker_executor.execute(tx_index);
    // No write was made by the transaction.
    assert_eq!(
        safe_versioned_state.pin_version(tx_index).get_nonce_at(account_address).unwrap(),
        nonce!(1_u8)
    );
    let execution_output = worker_executor.execution_outputs[tx_index].lock().unwrap();
    let execution_output = execution_output.as_ref().unwrap();
    assert!(execution_output.result.as_ref().is_err());
    let reads = StateMaps {
        nonces: HashMap::from([(account_address, nonce!(1_u8))]),
        ..Default::default()
    };
    assert_eq!(execution_output.reads, reads);
    assert_eq!(execution_output.writes, StateMaps::default());
    assert_eq!(execution_output.visited_pcs, HashMap::default());

    // Reverted execution.
    let tx_index = 2;
    worker_executor.execute(tx_index);
    // Read a write made by the transaction.
    assert_eq!(
        safe_versioned_state.pin_version(tx_index).get_nonce_at(account_address).unwrap(),
        nonce!(2_u8)
    );
    let execution_output = worker_executor.execution_outputs[tx_index].lock().unwrap();
    let execution_output = execution_output.as_ref().unwrap();
    assert!(execution_output.result.as_ref().unwrap().is_reverted());
    assert_ne!(execution_output.writes, StateMaps::default());
    assert_ne!(execution_output.visited_pcs, HashMap::default());

    // Validate status change.
    for tx_index in 0..3 {
        assert_eq!(*worker_executor.scheduler.get_tx_status(tx_index), TransactionStatus::Executed);
    }
}

#[test]
fn test_worker_validate() {
    // Settings.
    let concurrency_mode = true;
    let block_context =
        BlockContext::create_for_account_testing_with_concurrency_mode(concurrency_mode);

    let account_contract = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let chain_info = &block_context.chain_info;

    // Create the state.
    let state_reader =
        test_state_reader(chain_info, BALANCE, &[(account_contract, 1), (test_contract, 1)]);
    let safe_versioned_state = safe_versioned_state_for_testing(state_reader);

    // Create transactions.
    let test_contract_address = test_contract.get_instance_address(0);
    let account_address = account_contract.get_instance_address(0);
    let nonce_manager = &mut NonceManager::default();
    let storage_value0 = stark_felt!(93_u8);
    let storage_value1 = stark_felt!(39_u8);
    let storage_key = storage_key!(1993_u16);

    // Both transactions change the same storage key.
    let account_tx0 = account_invoke_tx(invoke_tx_args! {
        sender_address: account_address,
        calldata: create_calldata(
            test_contract_address,
            "test_storage_read_write",
            &[*storage_key.0.key(),storage_value0 ], // Calldata:  address, value.
        ),
        max_fee: Fee(MAX_FEE),
        nonce: nonce_manager.next(account_address)
    });

    let account_tx1 = account_invoke_tx(invoke_tx_args! {
        sender_address: account_address,
        calldata: create_calldata(
            test_contract_address,
            "test_storage_read_write",
            &[*storage_key.0.key(),storage_value1 ], // Calldata:  address, value.
        ),
        max_fee: Fee(MAX_FEE),
        nonce: nonce_manager.next(account_address)

    });

    // Concurrency settings.
    let txs = [account_tx0, account_tx1]
        .into_iter()
        .map(Transaction::AccountTransaction)
        .collect::<Vec<Transaction>>();

    let worker_executor = WorkerExecutor::new(safe_versioned_state.clone(), &txs, block_context);

    // Creates 2 active tasks.
    worker_executor.scheduler.next_task();
    worker_executor.scheduler.next_task();

    // Execute transactions in the wrong order, making the first execution invalid.
    worker_executor.execute(1);
    worker_executor.execute(0);

    // Creates 2 active tasks.
    worker_executor.scheduler.next_task();
    worker_executor.scheduler.next_task();

    // Validate succeeds.
    let tx_index = 0;
    let next_task = worker_executor.validate(tx_index);
    assert_eq!(next_task, Task::NoTask);
    // Verify writes exist in state.
    assert_eq!(
        safe_versioned_state
            .pin_version(tx_index)
            .get_storage_at(test_contract_address, storage_key)
            .unwrap(),
        storage_value0
    );
    // No status change.
    assert_eq!(*worker_executor.scheduler.get_tx_status(tx_index), TransactionStatus::Executed);

    // Validate failed. Invoke 2 failed validations; only the first leads to a re-execution.
    let tx_index = 1;
    let next_task1 = worker_executor.validate(tx_index);
    assert_eq!(next_task1, Task::ExecutionTask(tx_index));
    // Verify writes were removed.
    assert_eq!(
        safe_versioned_state
            .pin_version(tx_index)
            .get_storage_at(test_contract_address, storage_key)
            .unwrap(),
        storage_value0
    );
    // Verify status change.
    assert_eq!(*worker_executor.scheduler.get_tx_status(tx_index), TransactionStatus::Executing);

    let next_task2 = worker_executor.validate(tx_index);
    assert_eq!(next_task2, Task::NoTask);
}
use cairo_felt::Felt252;
use rstest::rstest;

#[rstest]
#[case::no_overflow(Fee(50_u128), stark_felt!(100_u128), StarkFelt::ZERO)]
#[case::overflow(Fee(150_u128), stark_felt!(u128::max_value()), stark_felt!(5_u128))]
#[case::overflow_edge_case(Fee(500_u128), stark_felt!(u128::max_value()), stark_felt!(u128::max_value()-1))]
pub fn test_add_fee_to_sequencer_balance(
    #[case] actual_fee: Fee,
    #[case] sequencer_balance_low: StarkFelt,
    #[case] sequencer_balance_high: StarkFelt,
) {
    let tx_index = 0;
    let block_context = BlockContext::create_for_account_testing_with_concurrency_mode(true);
    let account = FeatureContract::Empty(CairoVersion::Cairo1);
    let safe_versioned_state = safe_versioned_state_for_testing(test_state_reader(
        &block_context.chain_info,
        0,
        &[(account, 1)],
    ));
    let mut tx_versioned_state = safe_versioned_state.pin_version(tx_index);
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(&block_context);

    let fee_token_address = block_context.chain_info.fee_token_address(&FeeType::Strk);

    add_fee_to_sequencer_balance(
        fee_token_address,
        &mut tx_versioned_state,
        actual_fee,
        &block_context,
        sequencer_balance_low,
        sequencer_balance_high,
    );

    let new_sequencer_balance_value_low =
        tx_versioned_state.get_storage_at(fee_token_address, sequencer_balance_key_low).unwrap();
    let new_sequencer_balance_value_high =
        tx_versioned_state.get_storage_at(fee_token_address, sequencer_balance_key_high).unwrap();
    let expected_balance =
        (stark_felt_to_felt(sequencer_balance_low) + Felt252::from(actual_fee.0)).to_biguint();

    let mask_128_bit = (BigUint::from(1_u8) << 128) - 1_u8;
    let expected_sequencer_balance_value_low = Felt252::from(&expected_balance & mask_128_bit);
    let expected_sequencer_balance_value_high =
        stark_felt_to_felt(sequencer_balance_high) + Felt252::from(&expected_balance >> 128);

    assert_eq!(
        new_sequencer_balance_value_low,
        felt_to_stark_felt(&expected_sequencer_balance_value_low)
    );
    assert_eq!(
        new_sequencer_balance_value_high,
        felt_to_stark_felt(&expected_sequencer_balance_value_high)
    );
}

#[test]
fn test_deploy_before_declare() {
    // Create the state.
    let block_context = BlockContext::create_for_account_testing_with_concurrency_mode(true);
    let chain_info = &block_context.chain_info;
    let account_contract = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let state_reader = test_state_reader(chain_info, BALANCE, &[(account_contract, 2)]);
    let safe_versioned_state = safe_versioned_state_for_testing(state_reader);

    // Create transactions.
    let account_address_0 = account_contract.get_instance_address(0);
    let account_address_1 = account_contract.get_instance_address(1);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let test_class_hash = test_contract.get_class_hash();
    let test_class_info = calculate_class_info_for_testing(test_contract.get_class());
    let test_compiled_class_hash = test_contract.get_compiled_class_hash();

    let declare_tx = declare_tx(
        declare_tx_args! {
            max_fee: Fee(MAX_FEE),
            sender_address: account_address_0,
            version: TransactionVersion::THREE,
            resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
            class_hash: test_class_hash,
            compiled_class_hash: test_compiled_class_hash,
            nonce: nonce!(0_u8),
        },
        test_class_info.clone(),
    );

    // Deploy test contract.
    let invoke_tx = account_invoke_tx(invoke_tx_args! {
        sender_address: account_address_1,
        calldata: create_calldata(
            account_contract.get_instance_address(0),
            DEPLOY_CONTRACT_FUNCTION_ENTRY_POINT_NAME,
            &[
                test_class_hash.0,                  // Class hash.
                ContractAddressSalt::default().0,   // Salt.
                stark_felt!(2_u8),                  // Constructor calldata length.
                stark_felt!(1_u8),                  // Constructor calldata arg1.
                stark_felt!(1_u8),                  // Constructor calldata arg2.
            ]
        ),
        max_fee: Fee(MAX_FEE),
        nonce: nonce!(0_u8)
    });

    let txs = [declare_tx, invoke_tx]
        .into_iter()
        .map(Transaction::AccountTransaction)
        .collect::<Vec<Transaction>>();

    let worker_executor = WorkerExecutor::new(safe_versioned_state, &txs, block_context);

    // Creates 2 active tasks.
    worker_executor.scheduler.next_task();
    worker_executor.scheduler.next_task();

    // Execute transactions in the wrong order, making the first execution invalid.
    worker_executor.execute(1);
    worker_executor.execute(0);

    let execution_output = worker_executor.execution_outputs[1].lock().unwrap();
    let tx_execution_info = execution_output.as_ref().unwrap().result.as_ref().unwrap();
    assert!(tx_execution_info.is_reverted());
    assert!(tx_execution_info.revert_error.clone().unwrap().contains("not declared."));
    drop(execution_output);

    // Creates 2 active tasks.
    worker_executor.scheduler.next_task();
    worker_executor.scheduler.next_task();

    // Verify validation failed.
    assert_eq!(worker_executor.validate(1), Task::ExecutionTask(1));

    // Execute transaction 1 again.
    worker_executor.execute(1);

    let execution_output = worker_executor.execution_outputs[1].lock().unwrap();
    assert!(!execution_output.as_ref().unwrap().result.as_ref().unwrap().is_reverted());
    drop(execution_output);

    // Successful validatation for transaction 1.
    let next_task = worker_executor.validate(1);
    assert_eq!(next_task, Task::NoTask);
}
