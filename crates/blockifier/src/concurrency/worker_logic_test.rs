use std::collections::HashMap;

use rstest::rstest;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{Fee, TransactionVersion};
use starknet_api::{contract_address, patricia_key, stark_felt};

use super::WorkerExecutor;
use crate::abi::abi_utils::get_fee_token_var_address;
use crate::abi::sierra_types::next_storage_key;
use crate::concurrency::fee_utils::STORAGE_READ_SEQUENCER_BALANCE_INDICES;
use crate::concurrency::scheduler::{Task, TransactionStatus};
use crate::concurrency::test_utils::safe_versioned_state_for_testing;
use crate::concurrency::versioned_state::ThreadSafeVersionedState;
use crate::concurrency::worker_logic::lock_mutex_in_array;
use crate::context::BlockContext;
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::state::cached_state::{ContractClassMapping, StateMaps};
use crate::state::state_api::{StateReader, UpdatableState};
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state_reader;
use crate::test_utils::{
    create_calldata, create_trivial_calldata, CairoVersion, NonceManager, BALANCE, MAX_FEE,
    MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE, TEST_ERC20_CONTRACT_ADDRESS,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants::TRANSFER_ENTRY_POINT_NAME;
use crate::transaction::objects::FeeType;
use crate::transaction::test_utils::{account_invoke_tx, l1_resource_bounds};
use crate::transaction::transaction_execution::Transaction;
use crate::{invoke_tx_args, nonce, storage_key};

fn trivial_calldata_invoke_tx(
    account: FeatureContract,
    instance_id: u16,
    nonce_manager: &mut NonceManager,
) -> AccountTransaction {
    let account_address = account.get_instance_address(instance_id);
    account_invoke_tx(invoke_tx_args! {
        sender_address: account_address,
        calldata: create_trivial_calldata(account.get_instance_address(instance_id)),
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        version: TransactionVersion::THREE,
        nonce: nonce_manager.next(account_address),
    })
}

fn sequencer_transfer_invoke_tx(
    account: FeatureContract,
    block_context: &BlockContext,
    instance_id: u16,
    transfer_amount: u128,
    nonce_manager: &mut NonceManager,
) -> AccountTransaction {
    let sequencer_address = block_context.block_info.sequencer_address;
    let account_address = account.get_instance_address(instance_id);
    let transfer_calldata = create_calldata(
        block_context.chain_info().fee_token_address(&FeeType::Strk),
        TRANSFER_ENTRY_POINT_NAME,
        &[*sequencer_address.0.key(), stark_felt!(transfer_amount), stark_felt!(0_u8)],
    );

    // Invokes transfer to the sequencer.
    account_invoke_tx(invoke_tx_args! {
        sender_address: account_address,
        calldata: transfer_calldata,
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        version: TransactionVersion::THREE,
        nonce: nonce_manager.next(account_address)
    })
}

fn invoke_tx_without_calldata(
    account: FeatureContract,
    instance_id: u16,
    nonce_manager: &mut NonceManager,
) -> AccountTransaction {
    let account_address = account.get_instance_address(instance_id);
    account_invoke_tx(invoke_tx_args! {
        sender_address: account_address,
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        version: TransactionVersion::THREE,
        nonce: nonce_manager.next(account_address),
    })
}

fn validate_fee_transfer<S: StateReader>(
    executor: &WorkerExecutor<'_, S>,
    account: FeatureContract,
    instance_id: u16,
    tx_index: usize,
    expected_storage_values: (StarkFelt, StarkFelt, StarkFelt),
) {
    let tx_version_state = executor.state.pin_version(tx_index + 1);
    let account_balance_key_low =
        get_fee_token_var_address(account.get_instance_address(instance_id));

    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(&executor.block_context);
    for (balance, storage_key) in [
        (expected_storage_values.0, account_balance_key_low),
        (expected_storage_values.1, sequencer_balance_key_low),
        (expected_storage_values.2, sequencer_balance_key_high),
    ] {
        assert_eq!(
            tx_version_state
                .get_storage_at(
                    executor.block_context.chain_info.fee_token_address(&FeeType::Strk),
                    storage_key
                )
                .unwrap(),
            balance
        );
    }
}

fn write_account_balance_at_versioned_state(
    account: FeatureContract,
    state: &mut ThreadSafeVersionedState<impl StateReader>,
    tx_index: usize,
    account_id: u16,
    fee_token_address: ContractAddress,
    new_balance: StarkFelt,
) {
    let mut versioned_state = state.pin_version(tx_index - 1);
    let account_balance_key_low =
        get_fee_token_var_address(account.get_instance_address(account_id));
    let writes = StateMaps {
        storage: HashMap::from([((fee_token_address, account_balance_key_low), new_balance)]),
        ..StateMaps::default()
    };
    versioned_state.apply_writes(&writes, &ContractClassMapping::default(), &HashMap::default());
}

fn check_pre_commit_tx<S: StateReader>(
    executor: &WorkerExecutor<'_, S>,
    tx_index: usize,
    account: FeatureContract,
    account_id: u16,
    account_balance: u128,
    sequencer_balance_low: u128,
    should_fail: bool,
) {
    let execution_task_outputs = lock_mutex_in_array(&executor.execution_outputs, tx_index);
    let execution_result = &execution_task_outputs.as_ref().unwrap().result;
    assert_eq!(execution_result.is_err(), should_fail);
    let actual_fee = if should_fail { 0 } else { execution_result.as_ref().unwrap().actual_fee.0 };
    drop(execution_task_outputs);
    let sequencer_balance_high = 0_u128;
    // Check fee transfer before commit.
    validate_fee_transfer(
        executor,
        account,
        account_id,
        tx_index,
        (
            stark_felt!(account_balance - actual_fee),
            stark_felt!(sequencer_balance_low),
            stark_felt!(sequencer_balance_high),
        ),
    );
}

fn check_post_commit_tx<S: StateReader>(
    executor: &WorkerExecutor<'_, S>,
    tx_index: usize,
    account: FeatureContract,
    account_id: u16,
    account_balance: u128,
    sequencer_balance_low: u128,
    should_fail: bool,
) -> u128 {
    let execution_task_outputs = lock_mutex_in_array(&executor.execution_outputs, tx_index);
    let execution_result = &execution_task_outputs.as_ref().unwrap().result;
    assert_eq!(execution_result.is_err(), should_fail);
    // Extract the actual fee.
    let actual_fee = if should_fail { 0 } else { execution_result.as_ref().unwrap().actual_fee.0 };
    let sequencer_balance_high = 0_u128;
    let execution_result = &execution_task_outputs.as_ref().unwrap().result;

    if !should_fail {
        // Check that fill_sequencer_balance_reads worked after commit.
        for (index, expected_balance) in [
            (STORAGE_READ_SEQUENCER_BALANCE_INDICES.0, sequencer_balance_low),
            (STORAGE_READ_SEQUENCER_BALANCE_INDICES.1, sequencer_balance_high),
        ] {
            assert_eq!(
                execution_result
                    .as_ref()
                    .unwrap()
                    .fee_transfer_call_info
                    .as_ref()
                    .unwrap()
                    .storage_read_values[index],
                stark_felt!(expected_balance)
            );
        }
    }
    drop(execution_task_outputs);

    // Check fee transfer after commit.
    validate_fee_transfer(
        executor,
        account,
        account_id,
        tx_index,
        (
            stark_felt!(account_balance - actual_fee),
            stark_felt!(sequencer_balance_low + actual_fee),
            stark_felt!(sequencer_balance_high),
        ),
    );
    actual_fee
}

#[rstest]
pub fn test_commit_tx() {
    let block_context = BlockContext::create_for_testing_with_concurrency_mode(true);
    let transfer_amount = 50_u128;
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let mut sequencer_balance_low = 0_u128;
    let mut nonce_manager = NonceManager::default();

    // Create transactions.
    let transactions_array = [
        trivial_calldata_invoke_tx(account, 0_u16, &mut nonce_manager),
        sequencer_transfer_invoke_tx(
            account,
            &block_context,
            1_u16,
            transfer_amount,
            &mut nonce_manager,
        ),
        invoke_tx_without_calldata(account, 2_u16, &mut nonce_manager),
        trivial_calldata_invoke_tx(account, 3_u16, &mut nonce_manager),
        trivial_calldata_invoke_tx(account, 4_u16, &mut nonce_manager),
    ]
    .into_iter()
    .map(Transaction::AccountTransaction)
    .collect::<Vec<Transaction>>();

    let state_reader = test_state_reader(
        &block_context.chain_info,
        BALANCE,
        &[(account, transactions_array.len().try_into().unwrap())],
    );
    let versioned_state = safe_versioned_state_for_testing(state_reader);
    let mut executor = WorkerExecutor::new(versioned_state, &transactions_array, block_context);

    // tx0: pass execute -> pass re-validate ->  fix and commit.
    // This is an invoke transaction with trivial calldata.
    // We do not change any values in the read and write sets,
    // thus the transaction should pass the re-validate in the commit phase.
    let tx_index = 0;
    let account_id = 0_u16;
    let account_balance = BALANCE;
    let should_fail = false;
    executor.execute_tx(tx_index);
    check_pre_commit_tx(
        &executor,
        tx_index,
        account,
        account_id,
        account_balance,
        sequencer_balance_low,
        should_fail,
    );
    executor.commit_tx(tx_index).unwrap();
    let actual_fee = check_post_commit_tx(
        &executor,
        tx_index,
        account,
        account_id,
        account_balance,
        sequencer_balance_low,
        should_fail,
    );
    sequencer_balance_low += actual_fee;

    // tx1: pass execute -> fail re-validate ->  pass re-executed -> fixed and commit.
    // This is an invoke transaction with calldata that transfers an amount to the sequencer
    // balance. We change the sequencer balance in the write set, thus the transaction should
    // fail the re-validate in the commit phase, but pass the re-execute.
    let tx_index = 1;
    let account_id = 1_u16;
    let account_balance = BALANCE;
    let should_fail = false;
    executor.execute_tx(tx_index);
    check_pre_commit_tx(
        &executor,
        tx_index,
        account,
        account_id,
        account_balance - transfer_amount,
        sequencer_balance_low + transfer_amount,
        should_fail,
    );
    executor.commit_tx(tx_index).unwrap();
    let actual_fee = check_post_commit_tx(
        &executor,
        tx_index,
        account,
        account_id,
        account_balance - transfer_amount,
        sequencer_balance_low + transfer_amount,
        should_fail,
    );
    sequencer_balance_low += actual_fee + transfer_amount;

    // tx2: failed execute -> pass re-validate -> commit.
    // This is an invoke transaction with no call data, thus it should fail execution,
    // we do not change any values in the read and write sets, thus the transaction should pass the
    // re-validate in the commit phase.
    let account_id = 2_u16;
    let tx_index = 2;
    executor.execute_tx(tx_index);
    let should_fail = true;
    check_pre_commit_tx(
        &executor,
        tx_index,
        account,
        account_id,
        account_balance,
        sequencer_balance_low,
        should_fail,
    );
    executor.commit_tx(tx_index).unwrap();
    let actual_fee = check_post_commit_tx(
        &executor,
        tx_index,
        account,
        account_id,
        account_balance,
        sequencer_balance_low,
        should_fail,
    );

    sequencer_balance_low += actual_fee;

    // tx3: passed execute ->  failed re-validate ->  failed re-execute (rejected) -> commit.
    // This is an invoke transaction with trivial calldata. we change the account balance in the
    // write set, thus the transaction should fail the re-validate in the commit phase,
    // and becuse the ne account balance is zero, the re-execute should fail as well.
    let account_id = 3_u16;
    let tx_index = 3;
    let mut should_fail = false;
    executor.execute_tx(tx_index);
    check_pre_commit_tx(
        &executor,
        tx_index,
        account,
        account_id,
        account_balance,
        sequencer_balance_low,
        should_fail,
    );

    // Sets the account balance to zero so that the commit re-validation and re-execution will fail.
    let new_account_balance = 0_u128;
    write_account_balance_at_versioned_state(
        account,
        &mut executor.state,
        tx_index,
        account_id,
        executor.block_context.chain_info.fee_token_address(&FeeType::Strk),
        stark_felt!(new_account_balance),
    );
    executor.commit_tx(tx_index).unwrap();

    should_fail = true;
    let actual_fee = check_post_commit_tx(
        &executor,
        tx_index,
        account,
        account_id,
        new_account_balance,
        sequencer_balance_low,
        should_fail,
    );

    sequencer_balance_low += actual_fee;

    // tx4: failed execute -> failed revalidate -> passed re-execute -> commit.
    // This is an invoke transaction with trivial calldata. we change the account balance to zero
    // before the first execution, thus the transaction should fail the execution, then we change
    // the account balance back to BALANCE, thus the transaction should fail re-validate and pass
    // the re-execute in the commit phase.
    let account_id = 4_u16;
    let tx_index = 4;
    let new_account_balance = 0_u128;
    let mut should_fail = true;
    // Sets the account balance to zero so that the first execution of the transaction will fail.
    write_account_balance_at_versioned_state(
        account,
        &mut executor.state,
        tx_index,
        account_id,
        executor.block_context.chain_info.fee_token_address(&FeeType::Strk),
        stark_felt!(new_account_balance),
    );

    executor.execute_tx(tx_index);
    check_pre_commit_tx(
        &executor,
        tx_index,
        account,
        account_id,
        new_account_balance,
        sequencer_balance_low,
        should_fail,
    );

    // Sets the account balance back to BALANCE so that the commit re-validation will fail and the
    // re-execution will pass.
    write_account_balance_at_versioned_state(
        account,
        &mut executor.state,
        tx_index,
        account_id,
        executor.block_context.chain_info.fee_token_address(&FeeType::Strk),
        stark_felt!(BALANCE),
    );
    executor.commit_tx(tx_index).unwrap();
    should_fail = false;
    let _actual_fee = check_post_commit_tx(
        &executor,
        tx_index,
        account,
        account_id,
        account_balance,
        sequencer_balance_low,
        should_fail,
    );
}

#[test]
fn test_worker_execute() {
    // Settings.
    let concurrency_mode = true;
    let block_context = BlockContext::create_for_testing_with_concurrency_mode(concurrency_mode);
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
            .pin_version(tx_index + 1)
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
        safe_versioned_state.pin_version(tx_index + 1).get_nonce_at(account_address).unwrap(),
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
        safe_versioned_state.pin_version(tx_index + 1).get_nonce_at(account_address).unwrap(),
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
    let block_context = BlockContext::create_for_testing_with_concurrency_mode(concurrency_mode);

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
            .pin_version(tx_index + 1)
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
            .pin_version(tx_index + 1)
            .get_storage_at(test_contract_address, storage_key)
            .unwrap(),
        storage_value0
    );
    // Verify status change.
    assert_eq!(*worker_executor.scheduler.get_tx_status(tx_index), TransactionStatus::Executing);

    let next_task2 = worker_executor.validate(tx_index);
    assert_eq!(next_task2, Task::NoTask);
}
