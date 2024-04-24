use std::collections::HashMap;
use std::sync::Mutex;

use rstest::{fixture, rstest};
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::TransactionVersion;

use super::ExecutionTaskOutput;
use crate::abi::abi_utils::get_fee_token_var_address;
use crate::concurrency::scheduler::Scheduler;
use crate::concurrency::test_utils::safe_versioned_state_for_testing;
use crate::concurrency::versioned_state_proxy::VersionedStateProxy;
use crate::concurrency::worker_logic::{lock_mutex_in_array, WorkerExecutor};
use crate::context::BlockContext;
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::invoke_tx_args;
use crate::state::cached_state::{ContractClassMapping, StateMaps};
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state_reader;
use crate::test_utils::{
    create_calldata, create_trivial_calldata, CairoVersion, BALANCE, MAX_L1_GAS_AMOUNT,
    MAX_L1_GAS_PRICE,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants::TRANSFER_ENTRY_POINT_NAME;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::FeeType;
use crate::transaction::test_utils::{account_invoke_tx, l1_resource_bounds};
use crate::transaction::transaction_execution::Transaction;

fn trivial_call_data_transaction(account: FeatureContract, instance_id: u16) -> AccountTransaction {
    account_invoke_tx(invoke_tx_args! {
        sender_address: account.get_instance_address(instance_id),
        calldata: create_trivial_calldata(account.get_instance_address(instance_id)),
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        version: TransactionVersion::THREE
    })
}

fn sequencer_transfer_transaction(
    account: FeatureContract,
    block_context: &BlockContext,
    instance_id: u16,
    transfer_ammount: u128,
) -> AccountTransaction {
    let sequencer_address = block_context.block_info.sequencer_address;
    let transfer_calldata = create_calldata(
        block_context.chain_info().fee_token_address(&FeeType::Strk),
        TRANSFER_ENTRY_POINT_NAME,
        &[*sequencer_address.0.key(), stark_felt!(transfer_ammount), stark_felt!(0_u8)],
    );

    // Invokes transfer to the sequencer.
    account_invoke_tx(invoke_tx_args! {
        sender_address: account.get_instance_address(instance_id),
        calldata: transfer_calldata,
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        version: TransactionVersion::THREE
    })
}

fn invalid_transaction(account: FeatureContract, instance_id: u16) -> AccountTransaction {
    // Invokes transfer to the sequencer.
    account_invoke_tx(invoke_tx_args! {
        sender_address: account.get_instance_address(instance_id),
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        version: TransactionVersion::THREE
    })
}

fn validate_fee_transfer(
    block_context: &BlockContext,
    account: FeatureContract,
    instance_id: u16,
    tx_version_state: &VersionedStateProxy<impl StateReader>,
    expected_storage_values: (StarkFelt, StarkFelt, StarkFelt),
) {
    let account_balance_key_low =
        get_fee_token_var_address(account.get_instance_address(instance_id));

    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(block_context);
    // Check that before commiting the sender balance is updated and the sequencer balance is not.
    for (balance, storage_key) in [
        (expected_storage_values.0, account_balance_key_low),
        (expected_storage_values.1, sequencer_balance_key_low),
        (expected_storage_values.2, sequencer_balance_key_high),
    ] {
        assert_eq!(
            tx_version_state
                .get_storage_at(
                    block_context.chain_info.fee_token_address(&FeeType::Strk),
                    storage_key
                )
                .unwrap(),
            balance
        );
    }
}

#[fixture]
fn defulted_execution_task_output() -> ExecutionTaskOutput {
    ExecutionTaskOutput {
        reads: StateMaps::default(),
        writes: StateMaps::default(),
        visited_pcs: HashMap::default(),
        result: Err(TransactionExecutionError::TransactionTooLarge),
    }
}

#[rstest]
pub fn test_try_commit_transaction() {
    let block_context = BlockContext::create_for_testing_with_concurrency_mode(true);
    let transfer_ammount = 50_u128;
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let transactions_array = [
        Transaction::AccountTransaction(trivial_call_data_transaction(account, 0_u16)),
        Transaction::AccountTransaction(sequencer_transfer_transaction(
            account,
            &block_context,
            1_u16,
            transfer_ammount,
        )),
        Transaction::AccountTransaction(invalid_transaction(account, 2_u16)),
        Transaction::AccountTransaction(trivial_call_data_transaction(account, 3_u16)),
    ];
    let versioned_state = safe_versioned_state_for_testing(test_state_reader(
        &block_context.chain_info,
        BALANCE,
        &[(account, transactions_array.len().try_into().unwrap())],
    ));
    let execution_task_output_vec: Vec<_> =
        (0..transactions_array.len()).map(|_| Mutex::new(Option::None)).collect();

    let execution_task_output: Box<[Mutex<Option<ExecutionTaskOutput>>]> =
        execution_task_output_vec.into_boxed_slice();
    let executer = WorkerExecutor {
        state: versioned_state,
        chunk: Box::new(transactions_array),
        block_context,
        execution_outputs: execution_task_output,
        scheduler: Scheduler::default(),
    };
    for tx_index in 0..4 {
        executer.execute_tx(tx_index);
    }
    let account_balance = BALANCE;
    let mut sequencer_balance = 0_u128;
    for (tx_index, transfer_ammount, account_id) in
        [(0, 0_u128, 0_u16), (1, transfer_ammount, 1_u16)]
    {
        let execution_task_outputs = lock_mutex_in_array(&executer.execution_outputs, tx_index);
        let first_execution_result = &execution_task_outputs.as_ref().unwrap().result;
        assert!(first_execution_result.is_ok());
        let actual_fee = first_execution_result.as_ref().unwrap().actual_fee.0;
        drop(execution_task_outputs);
        validate_fee_transfer(
            &executer.block_context,
            account,
            account_id,
            &executer.state.pin_version(tx_index + 1),
            (
                stark_felt!(account_balance - actual_fee - transfer_ammount),
                stark_felt!(transfer_ammount),
                StarkFelt::ZERO,
            ),
        );
        executer.try_commit_transaction(tx_index).unwrap();
        validate_fee_transfer(
            &executer.block_context,
            account,
            account_id,
            &executer.state.pin_version(tx_index + 1),
            (
                stark_felt!(account_balance - actual_fee - transfer_ammount),
                stark_felt!(sequencer_balance + actual_fee + transfer_ammount),
                StarkFelt::ZERO,
            ),
        );
        sequencer_balance += actual_fee + transfer_ammount;
    }
    let account_id = 2_u16;
    let tx_index = 2;

    let execution_task_outputs = lock_mutex_in_array(&executer.execution_outputs, tx_index);
    let execution_result = &execution_task_outputs.as_ref().unwrap().result;
    assert!(execution_result.is_err());
    drop(execution_task_outputs);

    validate_fee_transfer(
        &executer.block_context,
        account,
        account_id,
        &executer.state.pin_version(tx_index + 1),
        (stark_felt!(account_balance), stark_felt!(sequencer_balance), StarkFelt::ZERO),
    );
    executer.try_commit_transaction(tx_index).unwrap();
    validate_fee_transfer(
        &executer.block_context,
        account,
        account_id,
        &executer.state.pin_version(tx_index + 1),
        (stark_felt!(account_balance), stark_felt!(sequencer_balance), StarkFelt::ZERO),
    );

    let account_id = 3_u16;
    let tx_index = 3;

    let execution_task_outputs = lock_mutex_in_array(&executer.execution_outputs, tx_index);
    let execution_result = &execution_task_outputs.as_ref().unwrap().result;
    assert!(execution_result.is_ok());
    let actual_fee = execution_result.as_ref().unwrap().actual_fee.0;
    drop(execution_task_outputs);
    validate_fee_transfer(
        &executer.block_context,
        account,
        account_id,
        &executer.state.pin_version(tx_index + 1),
        (
            stark_felt!(account_balance - actual_fee),
            stark_felt!(sequencer_balance),
            StarkFelt::ZERO,
        ),
    );
    let account_balance_key_low =
        get_fee_token_var_address(account.get_instance_address(account_id));
    let new_account_balance = StarkFelt::ZERO;
    let writes = StateMaps {
        storage: HashMap::from([(
            (
                executer.block_context.chain_info.fee_token_address(&FeeType::Strk),
                account_balance_key_low,
            ),
            new_account_balance,
        )]),
        ..StateMaps::default()
    };
    executer
        .state
        .pin_version(tx_index - 1)
        .apply_writes(&writes, &ContractClassMapping::default());
    executer.try_commit_transaction(tx_index).unwrap();
    let execution_task_outputs = lock_mutex_in_array(&executer.execution_outputs, tx_index);
    let execution_result = &execution_task_outputs.as_ref().unwrap().result;
    assert!(execution_result.is_err());
    drop(execution_task_outputs);
    // TODO(Meshi 01/06/2024): anccoment this when we will delete the transaction writes.
    // validate_fee_transfer(
    //     &executer.block_context,
    //     account,
    //     account_id,
    //     &executer.state.pin_version(tx_index + 1),
    //     (new_account_balance, stark_felt!(sequencer_balance), StarkFelt::ZERO),
    // );
}
