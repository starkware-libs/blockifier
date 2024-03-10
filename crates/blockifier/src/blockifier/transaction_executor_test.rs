use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::blockifier::bouncer::BouncerInfo;
use crate::blockifier::transaction_executor::TransactionExecutor;
use crate::context::BlockContext;
use crate::declare_tx_args;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::declare::declare_tx;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{CairoVersion, BALANCE, DEFAULT_STRK_L1_GAS_PRICE};
use crate::transaction::test_utils::{
    block_context, calculate_class_info_for_testing, l1_resource_bounds,
};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transactions::L1HandlerTransaction;

// Utils.

fn get_tx_for_tx_executor_test(
    tx_type: TransactionType,
    version: TransactionVersion,
    test_contract: FeatureContract,
    account_contract: FeatureContract,
) -> Transaction {
    let account_address = account_contract.get_instance_address(0);
    let contract_address = test_contract.get_instance_address(0);
    match tx_type {
        TransactionType::Declare => {
            let declared_contract = FeatureContract::Empty(CairoVersion::Cairo1); // Some unused contract.
            Transaction::AccountTransaction(declare_tx(
                declare_tx_args! {
                    sender_address: account_address,
                    class_hash: declared_contract.get_class_hash(),
                    version,
                    resource_bounds: l1_resource_bounds(0, DEFAULT_STRK_L1_GAS_PRICE),
                },
                calculate_class_info_for_testing(declared_contract.get_class()),
            ))
        }
        TransactionType::DeployAccount => todo!(),
        TransactionType::InvokeFunction => todo!(),
        TransactionType::L1Handler => Transaction::L1HandlerTransaction(
            L1HandlerTransaction::create_for_testing(Fee(1908000000000000), contract_address),
        ),
    }
}

#[rstest]
#[case::declare_tx(
    TransactionType::Declare, TransactionVersion::THREE, BouncerInfo {
        state_diff_size: 4,
        message_segment_length: 0,
        n_events: 0,
        ..Default::default()
    }
)]
#[case::l1_handler(
    TransactionType::L1Handler,
    TransactionVersion::ZERO, // The version of a L1HandlerTransaction is always zero.
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
    #[case] version: TransactionVersion,
    #[case] expected_bouncer_info: BouncerInfo,
    #[values(true, false)] charge_fee: bool,
) {
    // Setup context.
    let account_contract = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo0);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let state = test_state(
        &block_context.chain_info,
        BALANCE,
        &[(account_contract, 1), (test_contract, 1)],
    );

    // Create the tx executor.
    let mut tx_executor = TransactionExecutor::new(state, block_context);

    // Create the tested tx.
    let tx = get_tx_for_tx_executor_test(tx_type, version, test_contract, account_contract);
    // TODO(Arni, 30/03/2024): Consider adding a test for the transaction execution info. If A test
    // should not be added, rename the test to `test_bouncer_info`.
    // TODO(Arni, 30/03/2024): Test all fields of bouncer info.
    let (_tx_execution_info, bouncer_info) = tx_executor.execute(tx, charge_fee).unwrap();

    assert_eq!(bouncer_info.state_diff_size, expected_bouncer_info.state_diff_size);
    assert_eq!(bouncer_info.message_segment_length, expected_bouncer_info.message_segment_length);
    assert_eq!(bouncer_info.n_events, expected_bouncer_info.n_events);
}
