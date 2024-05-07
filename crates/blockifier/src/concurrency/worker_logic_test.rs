use rstest::rstest;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::TransactionVersion;

use crate::abi::abi_utils::get_fee_token_var_address;
use crate::concurrency::test_utils::safe_versioned_state_for_testing;
use crate::concurrency::versioned_state_proxy::VersionedStateProxy;
use crate::concurrency::worker_logic::try_commit_transaction;
use crate::context::BlockContext;
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::invoke_tx_args;
use crate::state::cached_state::CachedState;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state_reader;
use crate::test_utils::{
    create_calldata, create_trivial_calldata, CairoVersion, BALANCE, MAX_L1_GAS_AMOUNT,
    MAX_L1_GAS_PRICE,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants::TRANSFER_ENTRY_POINT_NAME;
use crate::transaction::objects::FeeType;
use crate::transaction::test_utils::{account_invoke_tx, l1_resource_bounds};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::ExecutableTransaction;

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
) -> AccountTransaction {
    let transfer_calldata = create_calldata(
        account.get_instance_address(instance_id),
        TRANSFER_ENTRY_POINT_NAME,
        &[
            *block_context.block_info.sequencer_address.0.key(),
            stark_felt!(50_u128),
            stark_felt!(0_u8),
        ],
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
    let transfer_calldata =
        create_calldata(account.get_instance_address(instance_id), "false_entry_point", &[]);

    // Invokes transfer to the sequencer.
    account_invoke_tx(invoke_tx_args! {
        sender_address: account.get_instance_address(instance_id),
        calldata: transfer_calldata,
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        version: TransactionVersion::THREE
    })
}

fn validate_fee_transfer(
    block_context: &BlockContext,
    account: FeatureContract,
    instance_id: u16,
    tx_version_state: &VersionedStateProxy<impl StateReader>,
    storage_values: (StarkFelt, StarkFelt, StarkFelt),
) {
    let account_balance_key_low =
        get_fee_token_var_address(account.get_instance_address(instance_id));
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(block_context);
    // Check that before commiting the sender balance is updated and the sequencer balance is not.
    for (balance, storage_key) in [
        (storage_values.0, account_balance_key_low),
        (storage_values.1, sequencer_balance_key_low),
        (storage_values.2, sequencer_balance_key_high),
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

#[rstest]
pub fn test_try_commit_transaction() {
    let mut block_context = BlockContext::create_for_testing_with_concurrency_mode(true);
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let mut versioned_state = safe_versioned_state_for_testing(test_state_reader(
        &block_context.chain_info,
        BALANCE,
        &[(account, 4)],
    ));
    let transactions_array = [
        Transaction::AccountTransaction(trivial_call_data_transaction(account, 0_u16)),
        Transaction::AccountTransaction(sequencer_transfer_transaction(
            account,
            &block_context,
            1_u16,
        )),
        Transaction::AccountTransaction(invalid_transaction(account, 2_u16)),
        Transaction::AccountTransaction(invalid_transaction(account, 3_u16)),
    ];

    let charge_fee = true;
    let validate = true;
    let mut cached_state = CachedState::from(versioned_state.pin_version(0));
    let mut transactional_state = CachedState::create_transactional(&mut cached_state);
    let mut execution_results = [
        transactions_array[0].execute_raw(
            &mut transactional_state,
            &block_context,
            charge_fee,
            validate,
        ),
        transactions_array[1].execute_raw(
            &mut transactional_state,
            &block_context,
            charge_fee,
            validate,
        ),
        transactions_array[2].execute_raw(
            &mut transactional_state,
            &block_context,
            charge_fee,
            validate,
        ),
        transactions_array[3].execute_raw(
            &mut transactional_state,
            &block_context,
            charge_fee,
            !validate,
        ),
    ];
    versioned_state.pin_version(0).apply_writes(
        &transactional_state.cache.borrow().writes,
        &transactional_state.class_hash_to_class.borrow(),
    );


    // First transaction no re-execution:
    let first_execution_result = &execution_results[0];
    let actual_fee = first_execution_result.as_ref().unwrap().actual_fee.0;
    assert!(first_execution_result.is_ok());
    validate_fee_transfer(
        &block_context,
        account,
        0_u16,
        &versioned_state.pin_version(1),
        (StarkFelt::from(BALANCE - actual_fee), StarkFelt::ZERO, StarkFelt::ZERO),
    );

    let read_set = &transactional_state.cache.borrow().initial_reads;
    try_commit_transaction(
        &mut versioned_state,
        0,
        &mut block_context,
        &transactions_array,
        &[read_set],
        &mut execution_results,
    )
    .unwrap();

    validate_fee_transfer(
        &block_context,
        account,
        0_u16,
        &versioned_state.pin_version(1),
        (stark_felt!(BALANCE - actual_fee), stark_felt!(actual_fee), StarkFelt::ZERO),
    );
}
