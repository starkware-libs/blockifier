use std::collections::HashMap;

use cairo_vm::vm::runners::builtin_runner::{
    BITWISE_BUILTIN_NAME, EC_OP_BUILTIN_NAME, HASH_BUILTIN_NAME, KECCAK_BUILTIN_NAME,
    OUTPUT_BUILTIN_NAME, POSEIDON_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME, SIGNATURE_BUILTIN_NAME,
};
use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::calldata;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, Fee, TransactionVersion};

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

// Utils.

/// Creates a builtin instance counter for testing. The counter is initialized with the default
/// value 0 for each builtin, and then the provided builtin_instance_counter is added to it.
fn build_expected_builtin_instance_counter(
    builtin_instance_counter: HashMap<String, usize>,
) -> HashMap<String, usize> {
    let mut expected_builtin_instance_counter = HashMap::from([
        (HASH_BUILTIN_NAME.to_string(), 0),
        (RANGE_CHECK_BUILTIN_NAME.to_string(), 0),
        (BITWISE_BUILTIN_NAME.to_string(), 0),
        (SIGNATURE_BUILTIN_NAME.to_string(), 0),
        (POSEIDON_BUILTIN_NAME.to_string(), 0),
        (EC_OP_BUILTIN_NAME.to_string(), 0),
        (KECCAK_BUILTIN_NAME.to_string(), 0),
        (OUTPUT_BUILTIN_NAME.to_string(), 0),
    ]);
    expected_builtin_instance_counter.extend(builtin_instance_counter);
    expected_builtin_instance_counter
}

#[rstest]
#[case::l1_handler(
    TransactionType::L1Handler,
    TransactionVersion::ZERO, // The transaction version for an L1HandlerTransaction is always 0.
    BouncerInfo {
        state_diff_size: 4,
        gas_weight: 11739,
        message_segment_length: 7,
        execution_resources: cairo_vm::vm::runners::cairo_runner::ExecutionResources {
            n_steps: 87423,
            n_memory_holes: 0,
            builtin_instance_counter: build_expected_builtin_instance_counter(HashMap::from([
                (HASH_BUILTIN_NAME.to_string(), 61),
                (POSEIDON_BUILTIN_NAME.to_string(), 7716),
                (RANGE_CHECK_BUILTIN_NAME.to_string(), 23),
            ])),
        },
        n_events: 0,
    }
)]

fn test_tx_executor(
    block_context: BlockContext,
    #[case] tx_type: TransactionType,
    #[case] _version: TransactionVersion,
    #[case] expected_bouncer_info: BouncerInfo,
    #[values(true, false)] charge_fee: bool,
) {
    // constants for the test.

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
                &calldata![
                    StarkFelt::from_u128(0x123), // from_address.
                    StarkFelt::from_u128(0x876), // key.
                    StarkFelt::from_u128(0x44)   // value.
                ],
                Fee(1908000000000000),
                test_contract.get_instance_address(0),
            ))
        }
    };

    let (_tx_execution_info, bouncer_info) = tx_executor.execute(tx, charge_fee).unwrap();

    assert_eq!(bouncer_info, expected_bouncer_info);
}
