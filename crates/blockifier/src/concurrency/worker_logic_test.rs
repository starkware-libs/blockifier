use std::collections::HashMap;

use num_bigint::BigUint;
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
use crate::concurrency::utils::lock_mutex_in_array;
use crate::concurrency::versioned_state::ThreadSafeVersionedState;
use crate::concurrency::worker_logic::add_fee_to_sequencer_balance;
use crate::context::BlockContext;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
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
    account_address: ContractAddress,
    nonce_manager: &mut NonceManager,
) -> AccountTransaction {
    account_invoke_tx(invoke_tx_args! {
        sender_address: account_address,
        calldata: create_trivial_calldata(account_address),
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        version: TransactionVersion::THREE,
        nonce: nonce_manager.next(account_address),
    })
}

fn sequencer_transfer_invoke_tx(
    account_address: ContractAddress,
    block_context: &BlockContext,
    transfer_amount: u128,
    nonce_manager: &mut NonceManager,
) -> AccountTransaction {
    let sequencer_address = block_context.block_info.sequencer_address;
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
    account_address: ContractAddress,
    nonce_manager: &mut NonceManager,
) -> AccountTransaction {
    account_invoke_tx(invoke_tx_args! {
        sender_address: account_address,
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        version: TransactionVersion::THREE,
        nonce: nonce_manager.next(account_address),
    })
}

// This function checks that the storage values of the account and sequencer balances in the
// versioned state of tx_index are equal to the expected_storage_values.
fn validate_fee_transfer<S: StateReader>(
    executor: &WorkerExecutor<'_, S>,
    account_address: ContractAddress,
    tx_index: usize,
    expected_storage_values: (StarkFelt, StarkFelt, StarkFelt, StarkFelt),
) {
    let tx_version_state = executor.state.pin_version(tx_index + 1);
    let account_balance_key_low = get_fee_token_var_address(account_address);
    let account_balance_key_high = next_storage_key(&account_balance_key_low).unwrap();

    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(&executor.block_context);

    for (balance, storage_key) in [
        (expected_storage_values.0, account_balance_key_low),
        (expected_storage_values.1, account_balance_key_high),
        (expected_storage_values.2, sequencer_balance_key_low),
        (expected_storage_values.3, sequencer_balance_key_high),
    ] {
        assert_eq!(
            balance,
            tx_version_state
                .get_storage_at(
                    executor.block_context.chain_info.fee_token_address(&FeeType::Strk),
                    storage_key
                )
                .unwrap()
        );
    }
}

fn write_account_balance_at_versioned_state(
    account_address: ContractAddress,
    state: &mut ThreadSafeVersionedState<impl StateReader>,
    tx_index: usize,
    fee_token_address: ContractAddress,
    new_balance_low: StarkFelt,
    new_balance_high: StarkFelt,
) {
    let mut versioned_state = state.pin_version(tx_index - 1);
    let account_balance_key_low = get_fee_token_var_address(account_address);
    let account_balance_key_high = next_storage_key(&account_balance_key_low).unwrap();
    let writes = StateMaps {
        storage: HashMap::from([
            ((fee_token_address, account_balance_key_low), new_balance_low),
            ((fee_token_address, account_balance_key_high), new_balance_high),
        ]),
        ..StateMaps::default()
    };
    versioned_state.apply_writes(&writes, &ContractClassMapping::default(), &HashMap::default());
}

fn subtract_with_overflow(a_low: u128, a_high: u128, b_low: u128, b_high: u128) -> (u128, u128) {
    let (low, overflow) = a_low.overflowing_sub(b_low);
    let high = a_high.wrapping_sub(b_high).wrapping_sub(overflow.into());
    (low, high)
}

fn add_with_overflow(a_low: u128, a_high: u128, b_low: u128, b_high: u128) -> (u128, u128) {
    let (low, overflow) = a_low.overflowing_add(b_low);
    let high = a_high.wrapping_add(b_high).wrapping_add(overflow.into());
    (low, high)
}

fn check_pre_commit_tx<S: StateReader>(
    executor: &WorkerExecutor<'_, S>,
    tx_index: usize,
    account_address: ContractAddress,
    account_balances: (u128, u128),
    sequencer_balances: (u128, u128),
    should_fail: bool,
) {
    let execution_task_outputs = lock_mutex_in_array(&executor.execution_outputs, tx_index);
    let execution_result = &execution_task_outputs.as_ref().unwrap().result;
    assert_eq!(execution_result.is_err(), should_fail);
    // Extract the actual fee. If the transaction fails, no fee should be charged.
    let actual_fee = if should_fail { 0 } else { execution_result.as_ref().unwrap().actual_fee.0 };
    let (account_balance_low, account_balance_high) =
        subtract_with_overflow(account_balances.0, account_balances.1, actual_fee, 0_u128);
    let (sequencer_balances_low, sequencer_balance_high) = sequencer_balances;
    drop(execution_task_outputs);
    // Check fee transfer before commit.
    validate_fee_transfer(
        executor,
        account_address,
        tx_index,
        (
            stark_felt!(account_balance_low),
            stark_felt!(account_balance_high),
            stark_felt!(sequencer_balances_low),
            stark_felt!(sequencer_balance_high),
        ),
    );
}

fn check_post_commit_tx<S: StateReader>(
    executor: &WorkerExecutor<'_, S>,
    tx_index: usize,
    account_address: ContractAddress,
    account_balances: (u128, u128),
    sequencer_balances: (u128, u128),
    should_fail: bool,
) -> u128 {
    let execution_task_outputs = lock_mutex_in_array(&executor.execution_outputs, tx_index);
    let execution_result = &execution_task_outputs.as_ref().unwrap().result;
    assert_eq!(execution_result.is_err(), should_fail);
    // Extract the actual fee. If the transaction fails, no fee should be charged.
    let actual_fee = if should_fail { 0 } else { execution_result.as_ref().unwrap().actual_fee.0 };
    let execution_result = &execution_task_outputs.as_ref().unwrap().result;
    let (sequencer_balance_low, sequencer_balance_high) = sequencer_balances;
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
    let (account_balance_low, account_balance_high) =
        subtract_with_overflow(account_balances.0, account_balances.1, actual_fee, 0_u128);
    let (sequencer_balance_low, sequencer_balance_high) =
        add_with_overflow(sequencer_balances.0, sequencer_balances.1, actual_fee, 0_u128);

    // Check fee transfer after commit.
    validate_fee_transfer(
        executor,
        account_address,
        tx_index,
        (
            stark_felt!(account_balance_low),
            stark_felt!(account_balance_high),
            stark_felt!(sequencer_balance_low),
            stark_felt!(sequencer_balance_high),
        ),
    );
    actual_fee
}

#[rstest]
pub fn test_commit_tx() {
    let block_context = BlockContext::create_for_account_testing_with_concurrency_mode(true);
    let transfer_amount = 50_u128;
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let mut sequencer_balance_low = 0_u128;
    let mut nonce_manager = NonceManager::default();

    // Create transactions.
    let transactions_array = [
        trivial_calldata_invoke_tx(account.get_instance_address(0_u16), &mut nonce_manager),
        sequencer_transfer_invoke_tx(
            account.get_instance_address(1_u16),
            &block_context,
            transfer_amount,
            &mut nonce_manager,
        ),
        invoke_tx_without_calldata(account.get_instance_address(2_u16), &mut nonce_manager),
        trivial_calldata_invoke_tx(account.get_instance_address(3_u16), &mut nonce_manager),
        trivial_calldata_invoke_tx(account.get_instance_address(4_u16), &mut nonce_manager),
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
    let account_address = account.get_instance_address(account_id);
    executor.execute_tx(tx_index);
    check_pre_commit_tx(
        &executor,
        tx_index,
        account_address,
        (account_balance, 0_u128),
        (sequencer_balance_low, 0_u128),
        should_fail,
    );
    executor.commit_tx(tx_index).unwrap();
    let actual_fee = check_post_commit_tx(
        &executor,
        tx_index,
        account_address,
        (account_balance, 0_u128),
        (sequencer_balance_low, 0_u128),
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
    let account_address = account.get_instance_address(account_id);
    check_pre_commit_tx(
        &executor,
        tx_index,
        account_address,
        (account_balance - transfer_amount, 0_u128),
        (sequencer_balance_low + transfer_amount, 0_u128),
        should_fail,
    );
    executor.commit_tx(tx_index).unwrap();
    let actual_fee = check_post_commit_tx(
        &executor,
        tx_index,
        account_address,
        (account_balance - transfer_amount, 0_u128),
        (sequencer_balance_low + transfer_amount, 0_u128),
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
    let account_address = account.get_instance_address(account_id);
    check_pre_commit_tx(
        &executor,
        tx_index,
        account_address,
        (account_balance, 0_u128),
        (sequencer_balance_low, 0_u128),
        should_fail,
    );
    executor.commit_tx(tx_index).unwrap();
    let actual_fee = check_post_commit_tx(
        &executor,
        tx_index,
        account_address,
        (account_balance, 0_u128),
        (sequencer_balance_low, 0_u128),
        should_fail,
    );

    sequencer_balance_low += actual_fee;

    // tx3: passed execute ->  failed re-validate ->  failed re-execute (rejected) -> fixed and
    // commit. This is an invoke transaction with trivial calldata. we change the account
    // balance in the write set, thus the transaction should fail the re-validate in the commit
    // phase, and becuse the ne account balance is zero, the re-execute should fail as well.
    let account_id = 3_u16;
    let tx_index = 3;
    let mut should_fail = false;
    let account_address = account.get_instance_address(account_id);
    executor.execute_tx(tx_index);
    check_pre_commit_tx(
        &executor,
        tx_index,
        account_address,
        (account_balance, 0_u128),
        (sequencer_balance_low, 0_u128),
        should_fail,
    );

    // Sets the account balance to zero so that the commit re-validation and re-execution will fail.
    let new_account_balance = 0_u128;
    write_account_balance_at_versioned_state(
        account_address,
        &mut executor.state,
        tx_index,
        executor.block_context.chain_info.fee_token_address(&FeeType::Strk),
        stark_felt!(new_account_balance),
        StarkFelt::ZERO,
    );
    executor.commit_tx(tx_index).unwrap();

    should_fail = true;
    let actual_fee = check_post_commit_tx(
        &executor,
        tx_index,
        account_address,
        (new_account_balance, 0_u128),
        (sequencer_balance_low, 0_u128),
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
    let account_address = account.get_instance_address(account_id);

    // Sets the account balance to zero so that the first execution of the transaction will fail.
    write_account_balance_at_versioned_state(
        account_address,
        &mut executor.state,
        tx_index,
        executor.block_context.chain_info.fee_token_address(&FeeType::Strk),
        stark_felt!(new_account_balance),
        StarkFelt::ZERO,
    );

    executor.execute_tx(tx_index);
    check_pre_commit_tx(
        &executor,
        tx_index,
        account_address,
        (new_account_balance, 0_u128),
        (sequencer_balance_low, 0_u128),
        should_fail,
    );

    // Sets the account balance back to BALANCE so that the commit re-validation will fail and the
    // re-execution will pass.
    write_account_balance_at_versioned_state(
        account_address,
        &mut executor.state,
        tx_index,
        executor.block_context.chain_info.fee_token_address(&FeeType::Strk),
        stark_felt!(BALANCE),
        StarkFelt::ZERO,
    );
    executor.commit_tx(tx_index).unwrap();
    should_fail = false;
    let _actual_fee = check_post_commit_tx(
        &executor,
        tx_index,
        account_address,
        (account_balance, 0_u128),
        (sequencer_balance_low, 0_u128),
        should_fail,
    );
}

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
    let next_tx_versioned_state = safe_versioned_state.pin_version(tx_index + 1);

    let new_sequencer_balance_value_low = next_tx_versioned_state
        .get_storage_at(fee_token_address, sequencer_balance_key_low)
        .unwrap();
    let new_sequencer_balance_value_high = next_tx_versioned_state
        .get_storage_at(fee_token_address, sequencer_balance_key_high)
        .unwrap();
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
