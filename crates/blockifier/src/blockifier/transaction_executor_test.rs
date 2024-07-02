use assert_matches::assert_matches;
use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::felt;
use starknet_api::transaction::{Fee, TransactionVersion};
use starknet_types_core::felt::Felt;

use crate::blockifier::config::TransactionExecutorConfig;
use crate::blockifier::transaction_executor::{
    TransactionExecutor, TransactionExecutorError, BLOCK_STATE_ACCESS_ERR,
};
use crate::bouncer::{Bouncer, BouncerWeights};
use crate::context::BlockContext;
use crate::state::cached_state::CachedState;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::declare::declare_tx;
use crate::test_utils::deploy_account::deploy_account_tx;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{
    create_calldata, CairoVersion, NonceManager, BALANCE, DEFAULT_STRK_L1_GAS_PRICE,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::test_utils::{
    account_invoke_tx, block_context, calculate_class_info_for_testing, create_test_init_data,
    emit_n_events_tx, l1_resource_bounds, TestInitData,
};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::L1HandlerTransaction;
use crate::{declare_tx_args, deploy_account_tx_args, invoke_tx_args, nonce};

fn tx_executor_test_body<S: StateReader>(
    state: CachedState<S>,
    block_context: BlockContext,
    tx: Transaction,
    expected_bouncer_weights: BouncerWeights,
) {
    let mut tx_executor =
        TransactionExecutor::new(state, block_context, TransactionExecutorConfig::default());
    // TODO(Arni, 30/03/2024): Consider adding a test for the transaction execution info. If A test
    // should not be added, rename the test to `test_bouncer_info`.
    // TODO(Arni, 30/03/2024): Test all bouncer weights.
    let _tx_execution_info = tx_executor.execute(&tx).unwrap();
    let bouncer_weights = tx_executor.bouncer.get_accumulated_weights();
    assert_eq!(bouncer_weights.state_diff_size, expected_bouncer_weights.state_diff_size);
    assert_eq!(
        bouncer_weights.message_segment_length,
        expected_bouncer_weights.message_segment_length
    );
    assert_eq!(bouncer_weights.n_events, expected_bouncer_weights.n_events);
}

#[rstest]
#[case::transaction_version_0(
    TransactionVersion::ZERO,
    CairoVersion::Cairo0,
    BouncerWeights {
        state_diff_size: 0,
        message_segment_length: 0,
        n_events: 0,
        ..Default::default()
    }
)]
#[case::transaction_version_1(
    TransactionVersion::ONE,
    CairoVersion::Cairo0,
    BouncerWeights {
        state_diff_size: 2,
        message_segment_length: 0,
        n_events: 0,
        ..Default::default()
    }
)]
#[case::transaction_version_2(
    TransactionVersion::TWO,
    CairoVersion::Cairo1,
    BouncerWeights {
        state_diff_size: 4,
        message_segment_length: 0,
        n_events: 0,
        ..Default::default()
    }
)]
#[case::transaction_version_3(
    TransactionVersion::THREE,
    CairoVersion::Cairo1,
    BouncerWeights {
        state_diff_size: 4,
        message_segment_length: 0,
        n_events: 0,
        ..Default::default()
    }
)]
fn test_declare(
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] account_cairo_version: CairoVersion,
    #[case] transaction_version: TransactionVersion,
    #[case] cairo_version: CairoVersion,
    #[case] expected_bouncer_weights: BouncerWeights,
) {
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let declared_contract = FeatureContract::Empty(cairo_version);
    let state = test_state(&block_context.chain_info, BALANCE, &[(account_contract, 1)]);

    let tx = Transaction::AccountTransaction(declare_tx(
        declare_tx_args! {
            sender_address: account_contract.get_instance_address(0),
            class_hash: declared_contract.get_class_hash(),
            compiled_class_hash: declared_contract.get_compiled_class_hash(),
            version: transaction_version,
            resource_bounds: l1_resource_bounds(0, DEFAULT_STRK_L1_GAS_PRICE),
        },
        calculate_class_info_for_testing(declared_contract.get_class()),
    ));
    tx_executor_test_body(state, block_context, tx, expected_bouncer_weights);
}

#[rstest]
fn test_deploy_account(
    block_context: BlockContext,
    #[values(TransactionVersion::ONE, TransactionVersion::THREE)] version: TransactionVersion,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
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
    let expected_bouncer_weights = BouncerWeights {
        state_diff_size: 3,
        message_segment_length: 0,
        n_events: 0,
        ..Default::default()
    };
    tx_executor_test_body(state, block_context, tx, expected_bouncer_weights);
}

#[rstest]
#[case::invoke_function_base_case(
    "assert_eq",
    vec![
        felt!(3_u32), // x.
        felt!(3_u32)  // y.
    ],
    BouncerWeights {
        state_diff_size: 2,
        message_segment_length: 0,
        n_events: 0,
        ..Default::default()
    }
)]
#[case::emit_event_syscall(
    "test_emit_events",
    vec![
        felt!(1_u32), // events_number.
        felt!(0_u32), // keys length.
        felt!(0_u32)  // data length.
    ],
    BouncerWeights {
        state_diff_size: 2,
        message_segment_length: 0,
        n_events: 1,
        ..Default::default()
    }
)]
#[case::storage_write_syscall(
    "test_count_actual_storage_changes",
    vec![],
    BouncerWeights {
        state_diff_size: 6,
        message_segment_length: 0,
        n_events: 0,
        ..Default::default()
    }
)]
fn test_invoke(
    block_context: BlockContext,
    #[values(TransactionVersion::ONE, TransactionVersion::THREE)] version: TransactionVersion,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
    #[case] entry_point_name: &str,
    #[case] entry_point_args: Vec<Felt>,
    #[case] expected_bouncer_weights: BouncerWeights,
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
    tx_executor_test_body(state, block_context, tx, expected_bouncer_weights);
}

#[rstest]
fn test_l1_handler(block_context: BlockContext) {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let state = test_state(&block_context.chain_info, BALANCE, &[(test_contract, 1)]);

    let tx = Transaction::L1HandlerTransaction(L1HandlerTransaction::create_for_testing(
        Fee(1908000000000000),
        test_contract.get_instance_address(0),
    ));
    let expected_bouncer_weights = BouncerWeights {
        state_diff_size: 4,
        message_segment_length: 7,
        n_events: 0,
        ..Default::default()
    };
    tx_executor_test_body(state, block_context, tx, expected_bouncer_weights);
}

#[rstest]
#[case::happy_flow(BouncerWeights::default(), 10)]
#[should_panic(expected = "BlockFull: Transaction cannot be added to the current block, block \
                           capacity reached.")]
#[case::block_full(
    BouncerWeights {
        n_events: 4,
        ..Default::default()
    },
    7
)]
#[should_panic(expected = "TransactionExecutionError(TransactionTooLarge): Transaction size \
                           exceeds the maximum block capacity.")]
#[case::transaction_too_large(BouncerWeights::default(), 11)]

fn test_bouncing(#[case] initial_bouncer_weights: BouncerWeights, #[case] n_events: usize) {
    let max_n_events_in_block = 10;
    let block_context = BlockContext::create_for_bouncer_testing(max_n_events_in_block);

    let TestInitData { state, account_address, contract_address, mut nonce_manager } =
        create_test_init_data(&block_context.chain_info, CairoVersion::Cairo1);

    // TODO(Yoni, 15/6/2024): turn on concurrency mode.
    let mut tx_executor =
        TransactionExecutor::new(state, block_context, TransactionExecutorConfig::default());

    tx_executor.bouncer.set_accumulated_weights(initial_bouncer_weights);

    tx_executor
        .execute(&Transaction::AccountTransaction(emit_n_events_tx(
            n_events,
            account_address,
            contract_address,
            nonce_manager.next(account_address),
        )))
        .map_err(|error| panic!("{error:?}: {error}"))
        .unwrap();
}

#[rstest]
fn test_execute_txs_bouncing() {
    let config = TransactionExecutorConfig::create_for_testing();
    let max_n_events_in_block = 10;
    let block_context = BlockContext::create_for_bouncer_testing(max_n_events_in_block);

    let TestInitData { state, account_address, contract_address, .. } =
        create_test_init_data(&block_context.chain_info, CairoVersion::Cairo1);

    let mut tx_executor = TransactionExecutor::new(state, block_context, config);

    let txs: Vec<Transaction> = [
        emit_n_events_tx(1, account_address, contract_address, nonce!(0_u32)),
        // Transaction too big.
        emit_n_events_tx(
            max_n_events_in_block + 1,
            account_address,
            contract_address,
            nonce!(1_u32),
        ),
        emit_n_events_tx(8, account_address, contract_address, nonce!(1_u32)),
        // No room for this in block - execution should halt.
        emit_n_events_tx(2, account_address, contract_address, nonce!(2_u32)),
        // Has room for this one, but should not be processed at all.
        emit_n_events_tx(1, account_address, contract_address, nonce!(3_u32)),
    ]
    .into_iter()
    .map(Transaction::AccountTransaction)
    .collect();

    // Run.
    let results = tx_executor.execute_txs(&txs);

    // Check execution results.
    let expected_offset = 3;
    assert_eq!(results.len(), expected_offset);

    assert!(results[0].is_ok());
    assert_matches!(
        results[1].as_ref().unwrap_err(),
        TransactionExecutorError::TransactionExecutionError(
            TransactionExecutionError::TransactionTooLarge
        )
    );
    assert!(results[2].is_ok());

    // Check state.
    assert_eq!(
        tx_executor
            .block_state
            .as_ref()
            .expect(BLOCK_STATE_ACCESS_ERR)
            .get_nonce_at(account_address)
            .unwrap(),
        nonce!(2_u32)
    );

    // Check idempotency: excess transactions should not be added.
    let remaining_txs = &txs[expected_offset..];
    let remaining_tx_results = tx_executor.execute_txs(remaining_txs);
    assert_eq!(remaining_tx_results.len(), 0);

    // Reset the bouncer and add the remaining transactions.
    tx_executor.bouncer = Bouncer::new(tx_executor.block_context.bouncer_config.clone());
    let remaining_tx_results = tx_executor.execute_txs(remaining_txs);

    assert_eq!(remaining_tx_results.len(), 2);
    assert!(remaining_tx_results[0].is_ok());
    assert!(remaining_tx_results[1].is_ok());
    assert_eq!(
        tx_executor
            .block_state
            .as_ref()
            .expect(BLOCK_STATE_ACCESS_ERR)
            .get_nonce_at(account_address)
            .unwrap(),
        nonce!(4_u32)
    );
}
