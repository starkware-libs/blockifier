use std::collections::{HashMap, HashSet};

use cairo_vm::types::builtin_name::BuiltinName;
use rstest::rstest;
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::{class_hash, contract_address, felt, patricia_key};

use super::BouncerConfig;
use crate::blockifier::transaction_executor::{
    TransactionExecutorError, TransactionExecutorResult,
};
use crate::bouncer::{verify_tx_weights_in_bounds, Bouncer, BouncerWeights, BuiltinCount};
use crate::context::BlockContext;
use crate::execution::call_info::ExecutionSummary;
use crate::state::cached_state::{StateChangesKeys, TransactionalState};
use crate::storage_key;
use crate::test_utils::initial_test_state::test_state;
use crate::transaction::errors::TransactionExecutionError;

#[test]
fn test_block_weights_has_room() {
    let max_bouncer_weights = BouncerWeights {
        builtin_count: BuiltinCount {
            add_mod: 10,
            bitwise: 10,
            ecdsa: 10,
            ec_op: 10,
            keccak: 10,
            mul_mod: 10,
            pedersen: 10,
            poseidon: 10,
            range_check: 10,
            range_check96: 10,
        },
        gas: 10,
        message_segment_length: 10,
        n_events: 10,
        n_steps: 10,
        state_diff_size: 10,
    };

    let bouncer_weights = BouncerWeights {
        builtin_count: BuiltinCount {
            add_mod: 6,
            bitwise: 6,
            ecdsa: 7,
            ec_op: 7,
            keccak: 8,
            mul_mod: 6,
            pedersen: 7,
            poseidon: 9,
            range_check: 10,
            range_check96: 10,
        },
        gas: 7,
        message_segment_length: 10,
        n_steps: 0,
        n_events: 2,
        state_diff_size: 7,
    };

    assert!(max_bouncer_weights.has_room(bouncer_weights));

    let bouncer_weights_exceeds_max = BouncerWeights {
        builtin_count: BuiltinCount {
            add_mod: 5,
            bitwise: 11,
            ecdsa: 5,
            ec_op: 5,
            keccak: 5,
            mul_mod: 5,
            pedersen: 5,
            poseidon: 5,
            range_check: 5,
            range_check96: 5,
        },
        gas: 5,
        message_segment_length: 5,
        n_steps: 5,
        n_events: 5,
        state_diff_size: 5,
    };

    assert!(!max_bouncer_weights.has_room(bouncer_weights_exceeds_max));
}

#[rstest]
#[case::empty_initial_bouncer(Bouncer::new(BouncerConfig::empty()))]
#[case::non_empty_initial_bouncer(Bouncer {
    executed_class_hashes: HashSet::from([class_hash!(0_u128)]),
    visited_storage_entries: HashSet::from([(
        contract_address!(0_u128),
        storage_key!(0_u128),
    )]),
    state_changes_keys: StateChangesKeys::create_for_testing(HashSet::from([
        ContractAddress::from(0_u128),
    ])),
    bouncer_config: BouncerConfig::empty(),
    accumulated_weights: BouncerWeights {
        builtin_count: BuiltinCount {
            add_mod: 10,
            bitwise: 10,
            ecdsa: 10,
            ec_op: 10,
            keccak: 10,
            mul_mod: 10,
            pedersen: 10,
            poseidon: 10,
            range_check: 10,
            range_check96: 10,
        },
        gas: 10,
        message_segment_length: 10,
        n_steps: 10,
        n_events: 10,
        state_diff_size: 10,
    },
})]
fn test_bouncer_update(#[case] initial_bouncer: Bouncer) {
    let execution_summary_to_update = ExecutionSummary {
        executed_class_hashes: HashSet::from([class_hash!(1_u128), class_hash!(2_u128)]),
        visited_storage_entries: HashSet::from([
            (ContractAddress::from(1_u128), storage_key!(1_u128)),
            (ContractAddress::from(2_u128), storage_key!(2_u128)),
        ]),
        ..Default::default()
    };

    let weights_to_update = BouncerWeights {
        builtin_count: BuiltinCount {
            add_mod: 0,
            bitwise: 1,
            ecdsa: 2,
            ec_op: 3,
            keccak: 4,
            mul_mod: 0,
            pedersen: 6,
            poseidon: 7,
            range_check: 8,
            range_check96: 0,
        },
        gas: 9,
        message_segment_length: 10,
        n_steps: 0,
        n_events: 1,
        state_diff_size: 2,
    };

    let state_changes_keys_to_update =
        StateChangesKeys::create_for_testing(HashSet::from([ContractAddress::from(1_u128)]));

    let mut updated_bouncer = initial_bouncer.clone();
    updated_bouncer.update(
        weights_to_update,
        &execution_summary_to_update,
        &state_changes_keys_to_update,
    );

    let mut expected_bouncer = initial_bouncer;
    expected_bouncer
        .executed_class_hashes
        .extend(&execution_summary_to_update.executed_class_hashes);
    expected_bouncer
        .visited_storage_entries
        .extend(&execution_summary_to_update.visited_storage_entries);
    expected_bouncer.state_changes_keys.extend(&state_changes_keys_to_update);
    expected_bouncer.accumulated_weights += weights_to_update;

    assert_eq!(updated_bouncer, expected_bouncer);
}

#[rstest]
#[case::positive_flow(1, Ok(()))]
#[case::block_full(11, Err(TransactionExecutorError::BlockFull))]
#[case::transaction_too_large(
    21,
    Err(TransactionExecutorError::TransactionExecutionError(
        TransactionExecutionError::TransactionTooLarge
    ))
)]
fn test_bouncer_try_update(
    #[case] added_ecdsa: usize,
    #[case] expected_result: TransactionExecutorResult<()>,
) {
    use cairo_vm::vm::runners::cairo_runner::ExecutionResources;

    use crate::transaction::objects::TransactionResources;

    let state = &mut test_state(&BlockContext::create_for_account_testing().chain_info, 0, &[]);
    let mut transactional_state = TransactionalState::create_transactional(state);

    // Setup the bouncer.
    let block_max_capacity = BouncerWeights {
        builtin_count: BuiltinCount {
            add_mod: 20,
            bitwise: 20,
            ecdsa: 20,
            ec_op: 20,
            keccak: 20,
            mul_mod: 20,
            pedersen: 20,
            poseidon: 20,
            range_check: 20,
            range_check96: 20,
        },
        gas: 20,
        message_segment_length: 20,
        n_steps: 20,
        n_events: 20,
        state_diff_size: 20,
    };
    let bouncer_config = BouncerConfig { block_max_capacity };

    let accumulated_weights = BouncerWeights {
        builtin_count: BuiltinCount {
            add_mod: 10,
            bitwise: 10,
            ecdsa: 10,
            ec_op: 10,
            keccak: 10,
            mul_mod: 10,
            pedersen: 10,
            poseidon: 10,
            range_check: 10,
            range_check96: 10,
        },
        gas: 10,
        message_segment_length: 10,
        n_steps: 10,
        n_events: 10,
        state_diff_size: 10,
    };

    let mut bouncer = Bouncer { accumulated_weights, bouncer_config, ..Default::default() };

    // Prepare the resources to be added to the bouncer.
    let execution_summary = ExecutionSummary { ..Default::default() };
    let builtin_counter = HashMap::from([
        (BuiltinName::bitwise, 1),
        (BuiltinName::ecdsa, added_ecdsa),
        (BuiltinName::ec_op, 1),
        (BuiltinName::keccak, 1),
        (BuiltinName::pedersen, 1),
        (BuiltinName::poseidon, 1),
        (BuiltinName::range_check, 1),
    ]);
    let tx_resources = TransactionResources {
        vm_resources: ExecutionResources {
            builtin_instance_counter: builtin_counter,
            ..Default::default()
        },
        ..Default::default()
    };
    let tx_state_changes_keys = transactional_state.get_actual_state_changes().unwrap().into_keys();

    // TODO(Yoni, 1/10/2024): simplify this test and move tx-too-large cases out.

    // Check that the transaction is not too large.
    let mut result = verify_tx_weights_in_bounds(
        &transactional_state,
        &execution_summary,
        &tx_resources,
        &tx_state_changes_keys,
        &bouncer.bouncer_config,
    )
    .map_err(TransactionExecutorError::TransactionExecutionError);

    if result.is_ok() {
        // Try to update the bouncer.
        result = bouncer.try_update(
            &transactional_state,
            &tx_state_changes_keys,
            &execution_summary,
            &tx_resources,
        );
    }

    // TODO(yael 27/3/24): compare the results without using string comparison.
    assert_eq!(format!("{:?}", result), format!("{:?}", expected_result));
}
