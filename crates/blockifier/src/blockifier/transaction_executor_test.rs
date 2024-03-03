use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::transaction::Fee;

use crate::blockifier::bouncer::BouncerInfo;
use crate::blockifier::transaction_executor::TransactionExecutor;
use crate::context::BlockContext;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{CairoVersion, BALANCE};
use crate::transaction::test_utils::block_context;
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transactions::L1HandlerTransaction;

#[rstest]
#[case::l1_handler(
    TransactionType::L1Handler,
    BouncerInfo {
        state_diff_size: 4,
        message_segment_length: 7,
        n_events: 0,
        ..Default::default()
    }
)]

fn test_tx_executor(
    block_context: BlockContext,
    #[case] tx_type: TransactionType,
    #[case] expected_bouncer_info: BouncerInfo,
    #[values(true, false)] charge_fee: bool,
) {
    // Setup context.
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let state = test_state(&block_context.chain_info, BALANCE, &[(test_contract, 1)]);

    // Create the tx executor.
    let mut tx_executor = TransactionExecutor::new(state, block_context);

    // Create the tested tx.
    let tx = match tx_type {
        TransactionType::Declare => todo!(),
        TransactionType::DeployAccount => todo!(),
        TransactionType::InvokeFunction => todo!(),
        TransactionType::L1Handler => {
            Transaction::L1HandlerTransaction(L1HandlerTransaction::create_for_testing(
                Fee(1908000000000000),
                test_contract.get_instance_address(0),
            ))
        }
    };
    // TODO(Arni, 30/03/2024): Consider adding a test for the transaction execution info. If A test
    // should not be added, rename the test to `test_bouncer_info`.
    // TODO(Arni, 30/03/2024): Test all fields of bouncer info.
    let (_tx_execution_info, bouncer_info) = tx_executor.execute(tx, charge_fee).unwrap();

    assert_eq!(bouncer_info.state_diff_size, expected_bouncer_info.state_diff_size);
    assert_eq!(bouncer_info.message_segment_length, expected_bouncer_info.message_segment_length);
    assert_eq!(bouncer_info.n_events, expected_bouncer_info.n_events);
}
