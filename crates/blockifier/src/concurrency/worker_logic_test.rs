use std::collections::HashMap;
use std::sync::Mutex;

use rstest::rstest;
use starknet_api::core::{ContractAddress, Nonce, PatriciaKey};
use starknet_api::transaction::{
    ContractAddressSalt, Fee, ResourceBoundsMapping, TransactionVersion,
};
use starknet_api::{contract_address, felt, patricia_key};
use starknet_types_core::felt::Felt;

use super::WorkerExecutor;
use crate::abi::abi_utils::get_fee_token_var_address;
use crate::abi::sierra_types::next_storage_key;
use crate::bouncer::Bouncer;
use crate::concurrency::fee_utils::STORAGE_READ_SEQUENCER_BALANCE_INDICES;
use crate::concurrency::scheduler::{Task, TransactionStatus};
use crate::concurrency::test_utils::safe_versioned_state_for_testing;
use crate::concurrency::versioned_state::ThreadSafeVersionedState;
use crate::concurrency::worker_logic::lock_mutex_in_array;
use crate::context::{BlockContext, TransactionContext};
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::state::cached_state::StateMaps;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::declare::declare_tx;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{
    create_calldata, create_trivial_calldata, CairoVersion, NonceManager, BALANCE,
    TEST_ERC20_CONTRACT_ADDRESS2,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants::DEPLOY_CONTRACT_FUNCTION_ENTRY_POINT_NAME;
use crate::transaction::objects::HasRelatedFeeType;
use crate::transaction::test_utils::{
    account_invoke_tx, calculate_class_info_for_testing, emit_n_events_tx, max_fee,
    max_resource_bounds,
};
use crate::transaction::transaction_execution::Transaction;
use crate::{declare_tx_args, invoke_tx_args, nonce, storage_key};

fn trivial_calldata_invoke_tx(
    account_address: ContractAddress,
    test_contract_address: ContractAddress,
    nonce: Nonce,
) -> AccountTransaction {
    account_invoke_tx(invoke_tx_args! {
        sender_address: account_address,
        calldata: create_trivial_calldata(test_contract_address),
        resource_bounds: max_resource_bounds(),
        nonce,
    })
}

/// Checks that the sequencer balance was updated as expected in the state.
fn verify_sequencer_balance_update<S: StateReader>(
    state: &ThreadSafeVersionedState<S>,
    tx_context: &TransactionContext,
    tx_index: usize,
    // We assume the balance is at most 2^128, so the "low" value is sufficient.
    expected_sequencer_balance_low: u128,
) {
    let TransactionContext { block_context, tx_info } = tx_context;
    let tx_version_state = state.pin_version(tx_index);
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(block_context);
    for (expected_balance, storage_key) in [
        (felt!(expected_sequencer_balance_low), sequencer_balance_key_low),
        (Felt::ZERO, sequencer_balance_key_high),
    ] {
        let actual_balance = tx_version_state
            .get_storage_at(
                block_context.chain_info.fee_token_address(&tx_info.fee_type()),
                storage_key,
            )
            .unwrap();
        assert_eq!(expected_balance, actual_balance);
    }
}

#[rstest]
pub fn test_commit_tx() {
    let block_context = BlockContext::create_for_account_testing();
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let mut expected_sequencer_balance_low = 0_u128;
    let mut nonce_manager = NonceManager::default();
    let account_address = account.get_instance_address(0);
    let test_contract_address = test_contract.get_instance_address(0);
    let first_nonce = nonce_manager.next(account_address);
    let second_nonce = nonce_manager.next(account_address);

    // Create transactions.
    let txs = [
        trivial_calldata_invoke_tx(account_address, test_contract_address, first_nonce),
        trivial_calldata_invoke_tx(account_address, test_contract_address, second_nonce),
        trivial_calldata_invoke_tx(account_address, test_contract_address, second_nonce),
        // Invalid nonce.
        trivial_calldata_invoke_tx(account_address, test_contract_address, nonce!(10_u8)),
    ]
    .into_iter()
    .map(Transaction::AccountTransaction)
    .collect::<Vec<Transaction>>();
    let mut bouncer = Bouncer::new(block_context.bouncer_config.clone());
    let cached_state =
        test_state(&block_context.chain_info, BALANCE, &[(account, 1), (test_contract, 1)]);
    let versioned_state = safe_versioned_state_for_testing(cached_state);
    let executor =
        WorkerExecutor::new(versioned_state, &txs, &block_context, Mutex::new(&mut bouncer));

    // Execute transactions.
    // Simulate a concurrent run by executing tx1 before tx0.
    // tx1 should fail execution since its nonce equals 1, and it is being executed before tx0,
    // whose nonce equals 0.
    // tx0 should pass execution.
    // tx2 should pass execution since its nonce equals 1, so executing it after tx0 should
    // succeed.
    // tx3 should fail execution regardless of execution order since its nonce
    // equals 10, where there are only four transactions.
    for &(execute_idx, should_fail_execution) in
        [(1, true), (0, false), (2, false), (3, true)].iter()
    {
        executor.execute_tx(execute_idx);
        let execution_task_outputs = lock_mutex_in_array(&executor.execution_outputs, execute_idx);
        let result = &execution_task_outputs.as_ref().unwrap().result;
        assert_eq!(result.is_err(), should_fail_execution);
        if !should_fail_execution {
            assert!(!result.as_ref().unwrap().is_reverted());
        }
    }

    // Commit all transactions in sequential order.
    // * tx0 should pass revalidation, fix the sequencer balance, fix the call info (fee transfer)
    //   and commit.
    // * tx1 should fail revalidation (it read the nonce before tx0 incremented it). It should pass
    //   re-execution (since tx0 incremented the nonce), fix the sequencer balance, fix the call
    //   info (fee transfer) and commit.
    // * tx2 should fail revalidation (it read the nonce before tx1 re-executed and incremented it).
    //   It should fail re-execution because it has the same nonce as tx1.
    // * tx3 should pass revalidation and commit.
    for &(commit_idx, should_fail_execution) in
        [(0, false), (1, false), (2, true), (3, true)].iter()
    {
        executor.commit_tx(commit_idx);
        let execution_task_outputs = lock_mutex_in_array(&executor.execution_outputs, commit_idx);
        let execution_result = &execution_task_outputs.as_ref().unwrap().result;
        let expected_sequencer_balance_high = 0_u128;
        assert_eq!(execution_result.is_err(), should_fail_execution);
        // Extract the actual fee. If the transaction fails, no fee should be charged.
        let actual_fee = if should_fail_execution {
            0
        } else {
            execution_result.as_ref().unwrap().transaction_receipt.fee.0
        };
        if !should_fail_execution {
            assert!(!execution_result.as_ref().unwrap().is_reverted());
            // Check that the call info was fixed.
            for (expected_sequencer_storage_read, read_storage_index) in [
                (expected_sequencer_balance_low, STORAGE_READ_SEQUENCER_BALANCE_INDICES.0),
                (expected_sequencer_balance_high, STORAGE_READ_SEQUENCER_BALANCE_INDICES.1),
            ] {
                let actual_sequencer_storage_read = execution_result
                    .as_ref()
                    .unwrap()
                    .fee_transfer_call_info
                    .as_ref()
                    .unwrap()
                    .storage_read_values[read_storage_index];
                assert_eq!(felt!(expected_sequencer_storage_read), actual_sequencer_storage_read,);
            }
        }
        let tx_context = executor.block_context.to_tx_context(&txs[commit_idx]);
        expected_sequencer_balance_low += actual_fee;
        // Check that the sequencer balance was updated correctly in the state.
        verify_sequencer_balance_update(
            &executor.state,
            &tx_context,
            commit_idx,
            expected_sequencer_balance_low,
        );
    }
}

#[test]
// When the sequencer is the sender, we use the sequential (full) fee transfer.
// Thus, we skip the last step of commit tx, meaning the execution result before and after
// commit tx should be the same (except for re-execution changes).
fn test_commit_tx_when_sender_is_sequencer() {
    let mut block_context = BlockContext::create_for_account_testing();
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let account_address = account.get_instance_address(0_u16);
    let test_contract_address = test_contract.get_instance_address(0_u16);
    block_context.block_info.sequencer_address = account_address;
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(&block_context);

    let sequencer_tx = [Transaction::AccountTransaction(trivial_calldata_invoke_tx(
        account_address,
        test_contract_address,
        nonce!(0_u8),
    ))];

    let mut bouncer = Bouncer::new(block_context.bouncer_config.clone());

    let state = test_state(&block_context.chain_info, BALANCE, &[(account, 1), (test_contract, 1)]);
    let versioned_state = safe_versioned_state_for_testing(state);
    let executor = WorkerExecutor::new(
        versioned_state,
        &sequencer_tx,
        &block_context,
        Mutex::new(&mut bouncer),
    );
    let tx_index = 0;
    let tx_versioned_state = executor.state.pin_version(tx_index);

    // Execute and save the execution result.
    executor.execute_tx(tx_index);
    let execution_task_outputs = lock_mutex_in_array(&executor.execution_outputs, tx_index);
    let execution_result = &execution_task_outputs.as_ref().unwrap().result;
    let fee_transfer_call_info =
        execution_result.as_ref().unwrap().fee_transfer_call_info.as_ref().unwrap();
    let read_values_before_commit = fee_transfer_call_info.storage_read_values.clone();
    drop(execution_task_outputs);

    let tx_context = &executor.block_context.to_tx_context(&sequencer_tx[0]);
    let fee_token_address =
        executor.block_context.chain_info.fee_token_address(&tx_context.tx_info.fee_type());
    let sequencer_balance_high_before =
        tx_versioned_state.get_storage_at(fee_token_address, sequencer_balance_key_high).unwrap();
    let sequencer_balance_low_before =
        tx_versioned_state.get_storage_at(fee_token_address, sequencer_balance_key_low).unwrap();

    // Commit tx and check that the commit made no changes in the execution result or the state.
    executor.commit_tx(tx_index);
    let execution_task_outputs = lock_mutex_in_array(&executor.execution_outputs, tx_index);
    let commit_result = &execution_task_outputs.as_ref().unwrap().result;
    let fee_transfer_call_info =
        commit_result.as_ref().unwrap().fee_transfer_call_info.as_ref().unwrap();
    // Check that the result call info is the same as before the commit.
    assert_eq!(read_values_before_commit, fee_transfer_call_info.storage_read_values);

    let sequencer_balance_low_after =
        tx_versioned_state.get_storage_at(fee_token_address, sequencer_balance_key_low).unwrap();
    let sequencer_balance_high_after =
        tx_versioned_state.get_storage_at(fee_token_address, sequencer_balance_key_high).unwrap();

    // Check that the sequencer balance is the same as before the commit.
    assert_eq!(sequencer_balance_low_before, sequencer_balance_low_after);
    assert_eq!(sequencer_balance_high_before, sequencer_balance_high_after);
}

#[rstest]
fn test_worker_execute(max_resource_bounds: ResourceBoundsMapping) {
    // Settings.
    let block_context = BlockContext::create_for_account_testing();
    let account_contract = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let chain_info = &block_context.chain_info;

    // Create the state.
    let state = test_state(chain_info, BALANCE, &[(account_contract, 1), (test_contract, 1)]);
    let safe_versioned_state = safe_versioned_state_for_testing(state);

    // Create transactions.
    let test_contract_address = test_contract.get_instance_address(0);
    let account_address = account_contract.get_instance_address(0);
    let nonce_manager = &mut NonceManager::default();
    let storage_value = felt!(93_u8);
    let storage_key = storage_key!(1993_u16);

    let tx_success = account_invoke_tx(invoke_tx_args! {
        sender_address: account_address,
        calldata: create_calldata(
            test_contract_address,
            "test_storage_read_write",
            &[*storage_key.0.key(),storage_value ], // Calldata:  address, value.
        ),
        resource_bounds: max_resource_bounds.clone(),
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
        resource_bounds: max_resource_bounds.clone(),
        nonce: nonce_manager.next(account_address)

    });

    let tx_revert = account_invoke_tx(invoke_tx_args! {
        sender_address: account_address,
        calldata: create_calldata(
            test_contract_address,
            "write_and_revert",
            &[felt!(1991_u16),storage_value ], // Calldata:  address, value.
        ),
        resource_bounds: max_resource_bounds,
        nonce: nonce_manager.next(account_address)

    });

    let txs = [tx_success, tx_failure, tx_revert]
        .into_iter()
        .map(Transaction::AccountTransaction)
        .collect::<Vec<Transaction>>();

    let mut bouncer = Bouncer::new(block_context.bouncer_config.clone());
    let worker_executor = WorkerExecutor::new(
        safe_versioned_state.clone(),
        &txs,
        &block_context,
        Mutex::new(&mut bouncer),
    );

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
    let account_balance = BALANCE - result.transaction_receipt.fee.0;
    assert!(!result.is_reverted());

    let erc20 = FeatureContract::ERC20(CairoVersion::Cairo0);
    let erc_contract_address = contract_address!(TEST_ERC20_CONTRACT_ADDRESS2);
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
            ((erc_contract_address, account_balance_key_low), felt!(account_balance)),
            ((erc_contract_address, account_balance_key_high), felt!(0_u8)),
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
            ((test_contract_address, storage_key), felt!(0_u8)),
            ((erc_contract_address, account_balance_key_low), felt!(BALANCE)),
            ((erc_contract_address, account_balance_key_high), felt!(0_u8)),
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

#[rstest]
fn test_worker_validate(max_resource_bounds: ResourceBoundsMapping) {
    // Settings.
    let block_context = BlockContext::create_for_account_testing();
    let account_contract = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let chain_info = &block_context.chain_info;

    // Create the state.
    let state = test_state(chain_info, BALANCE, &[(account_contract, 1), (test_contract, 1)]);
    let safe_versioned_state = safe_versioned_state_for_testing(state);

    // Create transactions.
    let test_contract_address = test_contract.get_instance_address(0);
    let account_address = account_contract.get_instance_address(0);
    let nonce_manager = &mut NonceManager::default();
    let storage_value0 = felt!(93_u8);
    let storage_value1 = felt!(39_u8);
    let storage_key = storage_key!(1993_u16);

    // Both transactions change the same storage key.
    let account_tx0 = account_invoke_tx(invoke_tx_args! {
        sender_address: account_address,
        calldata: create_calldata(
            test_contract_address,
            "test_storage_read_write",
            &[*storage_key.0.key(),storage_value0 ], // Calldata:  address, value.
        ),
        resource_bounds: max_resource_bounds.clone(),
        nonce: nonce_manager.next(account_address)
    });

    let account_tx1 = account_invoke_tx(invoke_tx_args! {
        sender_address: account_address,
        calldata: create_calldata(
            test_contract_address,
            "test_storage_read_write",
            &[*storage_key.0.key(),storage_value1 ], // Calldata:  address, value.
        ),
        resource_bounds: max_resource_bounds,
        nonce: nonce_manager.next(account_address)

    });

    let txs = [account_tx0, account_tx1]
        .into_iter()
        .map(Transaction::AccountTransaction)
        .collect::<Vec<Transaction>>();

    let mut bouncer = Bouncer::new(block_context.bouncer_config.clone());
    let worker_executor = WorkerExecutor::new(
        safe_versioned_state.clone(),
        &txs,
        &block_context,
        Mutex::new(&mut bouncer),
    );

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
    assert_eq!(next_task, Task::AskForTask);
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
    assert_eq!(next_task2, Task::AskForTask);
}

#[rstest]
#[case::declare_cairo0(CairoVersion::Cairo0, TransactionVersion::ONE)]
#[case::declare_cairo1(CairoVersion::Cairo1, TransactionVersion::THREE)]
fn test_deploy_before_declare(
    max_fee: Fee,
    max_resource_bounds: ResourceBoundsMapping,
    #[case] cairo_version: CairoVersion,
    #[case] version: TransactionVersion,
) {
    // Create the state.
    let block_context = BlockContext::create_for_account_testing();
    let chain_info = &block_context.chain_info;
    let account_contract = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let state = test_state(chain_info, BALANCE, &[(account_contract, 2)]);
    let safe_versioned_state = safe_versioned_state_for_testing(state);

    // Create transactions.
    let account_address_0 = account_contract.get_instance_address(0);
    let account_address_1 = account_contract.get_instance_address(1);
    let test_contract = FeatureContract::TestContract(cairo_version);
    let test_class_hash = test_contract.get_class_hash();
    let test_class_info = calculate_class_info_for_testing(test_contract.get_class());
    let test_compiled_class_hash = test_contract.get_compiled_class_hash();
    let declare_tx = declare_tx(
        declare_tx_args! {
            sender_address: account_address_0,
            resource_bounds: max_resource_bounds.clone(),
            class_hash: test_class_hash,
            compiled_class_hash: test_compiled_class_hash,
            version,
            max_fee,
            nonce: nonce!(0_u8),
        },
        test_class_info.clone(),
    );

    // Deploy test contract.
    let invoke_tx = account_invoke_tx(invoke_tx_args! {
        sender_address: account_address_1,
        calldata: create_calldata(
            account_address_0,
            DEPLOY_CONTRACT_FUNCTION_ENTRY_POINT_NAME,
            &[
                test_class_hash.0,                  // Class hash.
                ContractAddressSalt::default().0,   // Salt.
                felt!(2_u8),                  // Constructor calldata length.
                felt!(1_u8),                  // Constructor calldata arg1.
                felt!(1_u8),                  // Constructor calldata arg2.
            ]
        ),
        resource_bounds: max_resource_bounds,
        nonce: nonce!(0_u8)
    });

    let txs = [declare_tx, invoke_tx]
        .into_iter()
        .map(Transaction::AccountTransaction)
        .collect::<Vec<Transaction>>();

    let mut bouncer = Bouncer::new(block_context.bouncer_config.clone());
    let worker_executor =
        WorkerExecutor::new(safe_versioned_state, &txs, &block_context, Mutex::new(&mut bouncer));

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

    // Successful validation for transaction 1.
    let next_task = worker_executor.validate(1);
    assert_eq!(next_task, Task::AskForTask);
}

#[rstest]
fn test_worker_commit_phase(max_resource_bounds: ResourceBoundsMapping) {
    // Settings.
    let block_context = BlockContext::create_for_account_testing();
    let account_contract = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let chain_info = &block_context.chain_info;

    // Create the state.
    let state = test_state(chain_info, BALANCE, &[(account_contract, 1), (test_contract, 1)]);
    let safe_versioned_state = safe_versioned_state_for_testing(state);

    // Create transactions.
    let test_contract_address = test_contract.get_instance_address(0);
    let sender_address = account_contract.get_instance_address(0);
    let nonce_manager = &mut NonceManager::default();
    let storage_value = felt!(93_u8);
    let storage_key = storage_key!(1993_u16);
    let calldata = create_calldata(
        test_contract_address,
        "test_storage_read_write",
        &[*storage_key.0.key(), storage_value], // Calldata:  address, value.
    );

    let txs = (0..3)
        .map(|_| {
            Transaction::AccountTransaction(account_invoke_tx(invoke_tx_args! {
                sender_address,
                calldata: calldata.clone(),
                resource_bounds: max_resource_bounds.clone(),
                nonce: nonce_manager.next(sender_address)
            }))
        })
        .collect::<Vec<Transaction>>();

    let mut bouncer = Bouncer::new(block_context.bouncer_config.clone());
    let worker_executor =
        WorkerExecutor::new(safe_versioned_state, &txs, &block_context, Mutex::new(&mut bouncer));

    // Try to commit before any transaction is ready.
    worker_executor.commit_while_possible();

    // Verify no transaction was committed.
    assert_eq!(worker_executor.scheduler.get_n_committed_txs(), 0);

    // Creates 2 active tasks.
    // Creating these tasks changes the status of the first two transactions to `Executing`. If we
    // skip this step, executing them will panic when reaching `finish_execution` (as their status
    // will be `ReadyToExecute` and not `Executing` as expected).
    assert_eq!(worker_executor.scheduler.next_task(), Task::ExecutionTask(0));
    assert_eq!(worker_executor.scheduler.next_task(), Task::ExecutionTask(1));

    // Execute the first two transactions.
    worker_executor.execute(0);
    worker_executor.execute(1);

    // Commit the first two transactions (only).
    worker_executor.commit_while_possible();

    // Verify the commit index is now 2.
    assert_eq!(worker_executor.scheduler.get_n_committed_txs(), 2);

    // Verify the status of the first two transactions is `Committed`.
    assert_eq!(*worker_executor.scheduler.get_tx_status(0), TransactionStatus::Committed);
    assert_eq!(*worker_executor.scheduler.get_tx_status(1), TransactionStatus::Committed);

    // Create the final execution task and execute it.
    assert_eq!(worker_executor.scheduler.next_task(), Task::ExecutionTask(2));
    worker_executor.execute(2);

    // Commit the third (and last) transaction.
    worker_executor.commit_while_possible();

    // Verify the number of committed transactions is 3, the status of the last transaction is
    // `Committed`, and the next task is `Done`.
    assert_eq!(worker_executor.scheduler.get_n_committed_txs(), 3);
    assert_eq!(*worker_executor.scheduler.get_tx_status(2), TransactionStatus::Committed);
    assert_eq!(worker_executor.scheduler.next_task(), Task::Done);

    // Try to commit when all transactions are already committed.
    worker_executor.commit_while_possible();
    assert_eq!(worker_executor.scheduler.get_n_committed_txs(), 3);

    // Make sure all transactions were executed successfully.
    for execution_output in worker_executor.execution_outputs.iter() {
        let locked_execution_output = execution_output.lock().unwrap();
        let result = locked_execution_output.as_ref().unwrap().result.as_ref();
        assert!(!result.unwrap().is_reverted());
    }
}

#[rstest]
fn test_worker_commit_phase_with_halt() {
    // Settings.
    let max_n_events_in_block = 3;
    let block_context = BlockContext::create_for_bouncer_testing(max_n_events_in_block);

    let account_contract = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let chain_info = &block_context.chain_info;

    // Create the state.
    let state = test_state(chain_info, BALANCE, &[(account_contract, 1), (test_contract, 1)]);
    let safe_versioned_state = safe_versioned_state_for_testing(state);

    // Create transactions.
    let test_contract_address = test_contract.get_instance_address(0);
    let sender_address = account_contract.get_instance_address(0);
    let nonce_manager = &mut NonceManager::default();
    // Create two transactions with 2 events to trigger block full (if we use a single transaction
    // and simply set the maximal number of events per block to 1, the transaction will fail with a
    // different error, it will be too large to fit a block - even by itself).
    let n_events = max_n_events_in_block - 1;

    let txs = (0..2)
        .map(|_| {
            Transaction::AccountTransaction(emit_n_events_tx(
                n_events,
                sender_address,
                test_contract_address,
                nonce_manager.next(sender_address),
            ))
        })
        .collect::<Vec<Transaction>>();

    let mut bouncer = Bouncer::new(block_context.bouncer_config.clone());
    let worker_executor =
        WorkerExecutor::new(safe_versioned_state, &txs, &block_context, Mutex::new(&mut bouncer));

    // Creates 2 active tasks.
    // Creating these tasks changes the status of both transactions to `Executing`. If we skip this
    // step, executing them will panic when reaching `finish_execution` (as their status will be
    // `ReadyToExecute` and not `Executing` as expected).
    assert_eq!(worker_executor.scheduler.next_task(), Task::ExecutionTask(0));
    assert_eq!(worker_executor.scheduler.next_task(), Task::ExecutionTask(1));

    // Execute both transactions.
    worker_executor.execute(0);
    worker_executor.execute(1);

    // Commit both transactions.
    worker_executor.commit_while_possible();

    // Verify the scheduler is halted.
    assert_eq!(worker_executor.scheduler.next_task(), Task::Done);

    // Verify the status of both transactions is `Committed`.
    assert_eq!(*worker_executor.scheduler.get_tx_status(0), TransactionStatus::Committed);
    assert_eq!(*worker_executor.scheduler.get_tx_status(1), TransactionStatus::Committed);

    // Verify that only one transaction was in fact committed.
    assert_eq!(worker_executor.scheduler.get_n_committed_txs(), 1);

    // Make sure all transactions were executed successfully.
    for execution_output in worker_executor.execution_outputs.iter() {
        let locked_execution_output = execution_output.lock().unwrap();
        let result = locked_execution_output.as_ref().unwrap().result.as_ref();
        assert!(!result.unwrap().is_reverted());
    }
}
