use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::transaction::Fee;

use crate::blockifier::bouncer::BouncerInfo;
use crate::blockifier::transaction_executor::TransactionExecutor;
use crate::bouncer::BouncerConfig;
use crate::context::BlockContext;
use crate::state::cached_state::CachedState;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{CairoVersion, BALANCE};
use crate::transaction::test_utils::block_context;
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::L1HandlerTransaction;

fn tx_executor_test_body<S: StateReader>(
    state: CachedState<S>,
    block_context: BlockContext,
    tx: Transaction,
    charge_fee: bool,
    expected_bouncer_info: BouncerInfo,
) {
    let mut tx_executor =
        TransactionExecutor::new(state, block_context, BouncerConfig::create_for_testing());
    // TODO(Arni, 30/03/2024): Consider adding a test for the transaction execution info. If A test
    // should not be added, rename the test to `test_bouncer_info`.
    // TODO(Arni, 30/03/2024): Test all fields of bouncer info.
    let (_tx_execution_info, bouncer_info) = tx_executor.execute(tx, charge_fee).unwrap();

    assert_eq!(bouncer_info.state_diff_size, expected_bouncer_info.state_diff_size);
    assert_eq!(bouncer_info.message_segment_length, expected_bouncer_info.message_segment_length);
    assert_eq!(bouncer_info.n_events, expected_bouncer_info.n_events);
}

#[rstest]
fn test_tx_executor_on_l1_handler(
    block_context: BlockContext,
    #[values(true, false)] charge_fee: bool,
) {
    // Setup context.
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let state = test_state(&block_context.chain_info, BALANCE, &[(test_contract, 1)]);

    // Create the tested transaction and run it with the transaction executor.
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
