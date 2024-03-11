use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::blockifier::bouncer::BouncerInfo;
use crate::blockifier::transaction_executor::TransactionExecutor;
use crate::context::BlockContext;
use crate::state::cached_state::CachedState;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::deploy_account::deploy_account_tx;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{
    create_calldata, CairoVersion, NonceManager, BALANCE, DEFAULT_STRK_L1_GAS_PRICE,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::test_utils::{account_invoke_tx, block_context, l1_resource_bounds};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::L1HandlerTransaction;
use crate::{deploy_account_tx_args, invoke_tx_args};

fn tx_executor_test_body<S: StateReader>(
    state: CachedState<S>,
    block_context: BlockContext,
    tx: Transaction,
    charge_fee: bool,
    expected_bouncer_info: BouncerInfo,
) {
    let mut tx_executor = TransactionExecutor::new(state, block_context);
    // TODO(Arni, 30/03/2024): Consider adding a test for the transaction execution info. If A test
    // should not be added, rename the test to `test_bouncer_info`.
    // TODO(Arni, 30/03/2024): Test all fields of bouncer info.
    let (_tx_execution_info, bouncer_info) = tx_executor.execute(tx, charge_fee).unwrap();

    assert_eq!(bouncer_info.state_diff_size, expected_bouncer_info.state_diff_size);
    assert_eq!(bouncer_info.message_segment_length, expected_bouncer_info.message_segment_length);
    assert_eq!(bouncer_info.n_events, expected_bouncer_info.n_events);
}

#[rstest]
fn test_tx_executor_on_deploy_account(
    block_context: BlockContext,
    #[values(TransactionVersion::ONE, TransactionVersion::THREE)] version: TransactionVersion,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
    #[values(true, false)] charge_fee: bool,
) {
    let account_contract = FeatureContract::AccountWithoutValidations(cairo_version);
    let state = test_state(&block_context.chain_info, BALANCE, &[(account_contract, 0)]);

    let tx = Transaction::AccountTransaction(AccountTransaction::DeployAccount(deploy_account_tx(
        deploy_account_tx_args! {
            class_hash: account_contract.get_class_hash(),
            resource_bounds: l1_resource_bounds(0, DEFAULT_STRK_L1_GAS_PRICE),
            version,
        },
        &mut NonceManager::default(),
    )));
    let expected_bouncer_info = BouncerInfo {
        state_diff_size: 3,
        message_segment_length: 0,
        n_events: 0,
        ..Default::default()
    };
    tx_executor_test_body(state, block_context, tx, charge_fee, expected_bouncer_info);
}

#[rstest]
#[case::invoke_function(
    "assert_eq",
    vec![
        stark_felt!(3_u32), // x.
        stark_felt!(3_u32)  // y.
    ],
    BouncerInfo {
        state_diff_size: 2,
        message_segment_length: 0,
        n_events: 0,
        ..Default::default()
    }
)]
#[case::emit_event(
    "test_emit_events",
    vec![
        stark_felt!(1_u32), // events_number.
        stark_felt!(0_u32), // keys length.
        stark_felt!(0_u32)  // data length.
    ],
    BouncerInfo {
        state_diff_size: 2,
        message_segment_length: 0,
        n_events: 1,
        ..Default::default()
    }
)]
fn test_tx_executor_on_invoke(
    block_context: BlockContext,
    #[values(true, false)] charge_fee: bool,
    #[values(TransactionVersion::ONE, TransactionVersion::THREE)] version: TransactionVersion,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
    #[case] entry_point_name: &str,
    #[case] entry_point_args: Vec<StarkFelt>,
    #[case] expected_bouncer_info: BouncerInfo,
) {
    let test_contract = FeatureContract::TestContract(cairo_version);
    let account_contract = FeatureContract::AccountWithoutValidations(cairo_version);
    let state = test_state(
        &block_context.chain_info,
        BALANCE,
        &[(test_contract, 1), (account_contract, 1)],
    );

    let calldata =
        create_calldata(test_contract.get_instance_address(0), entry_point_name, &entry_point_args);
    let tx = Transaction::AccountTransaction(account_invoke_tx(invoke_tx_args! {
        sender_address: account_contract.get_instance_address(0),
        calldata,
        version,
    }));
    tx_executor_test_body(state, block_context, tx, charge_fee, expected_bouncer_info);
}

#[rstest]
fn test_tx_executor_on_l1_handler(
    block_context: BlockContext,
    #[values(true, false)] charge_fee: bool,
) {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let state = test_state(&block_context.chain_info, BALANCE, &[(test_contract, 1)]);

    let tx = Transaction::L1HandlerTransaction(L1HandlerTransaction::create_for_testing(
        Fee(1908000000000000),
        test_contract.get_instance_address(0),
    ));
    let expected_bouncer_info = BouncerInfo {
        state_diff_size: 4,
        message_segment_length: 7,
        n_events: 0,
        ..Default::default()
    };
    tx_executor_test_body(state, block_context, tx, charge_fee, expected_bouncer_info);
}
