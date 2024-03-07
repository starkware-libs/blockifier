use std::collections::HashMap;
use std::ops::Sub;

use assert_matches::assert_matches;
use cairo_vm::serde::deserialize_program::BuiltinName;

use super::BouncerConfig;
use crate::abi::constants;
use crate::blockifier::transaction_executor::TransactionExecutorError;
use crate::bouncer::{Bouncer, BouncerWeights, BuiltinCount};
use crate::context::BlockContext;
use crate::execution::call_info::ExecutionSummary;
use crate::state::cached_state::CachedState;
use crate::test_utils::initial_test_state::test_state;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::ResourcesMapping;

#[test]
fn test_block_weights_sub_checked() {
    let max_bouncer_weights = BouncerWeights {
        builtin_count: BuiltinCount {
            bitwise: 10,
            ecdsa: 10,
            ec_op: 10,
            keccak: 10,
            pedersen: 10,
            poseidon: 10,
            range_check: 10,
        },
        gas: 10,
        message_segment_length: 10,
        n_events: 10,
        n_steps: 10,
        state_diff_size: 10,
    };

    let bouncer_weights = BouncerWeights {
        builtin_count: BuiltinCount {
            bitwise: 6,
            ecdsa: 7,
            ec_op: 7,
            keccak: 8,
            pedersen: 7,
            poseidon: 9,
            range_check: 10,
        },
        gas: 7,
        message_segment_length: 10,
        n_steps: 0,
        n_events: 2,
        state_diff_size: 7,
    };

    let result = max_bouncer_weights.checked_sub(bouncer_weights).unwrap();
    let difference_bouncer_weights = max_bouncer_weights.sub(bouncer_weights);
    assert_eq!(result, difference_bouncer_weights);

    let bouncer_weights_exceeds_max = BouncerWeights {
        builtin_count: BuiltinCount {
            bitwise: 11,
            ecdsa: 5,
            ec_op: 5,
            keccak: 5,
            pedersen: 5,
            poseidon: 5,
            range_check: 5,
        },
        gas: 5,
        message_segment_length: 5,
        n_steps: 5,
        n_events: 5,
        state_diff_size: 5,
    };

    let result = max_bouncer_weights.checked_sub(bouncer_weights_exceeds_max);
    assert!(result.is_none());
}

#[test]
fn test_transactional_bouncer() {
    let initial_bouncer_weights = BouncerWeights {
        builtin_count: BuiltinCount {
            bitwise: 10,
            ecdsa: 10,
            ec_op: 10,
            keccak: 10,
            pedersen: 10,
            poseidon: 10,
            range_check: 10,
        },
        gas: 10,
        message_segment_length: 10,
        n_steps: 10,
        n_events: 10,
        state_diff_size: 10,
    };

    let weights_to_commit = BouncerWeights {
        builtin_count: BuiltinCount {
            bitwise: 1,
            ecdsa: 2,
            ec_op: 3,
            keccak: 4,
            pedersen: 6,
            poseidon: 7,
            range_check: 8,
        },
        gas: 9,
        message_segment_length: 10,
        n_steps: 0,
        n_events: 1,
        state_diff_size: 2,
    };

    let bouncer = Bouncer::new(initial_bouncer_weights, true);
    let mut transactional_bouncer = bouncer.create_transactional();
    transactional_bouncer.transactional.available_capacity = weights_to_commit;

    // Test transactional bouncer abort.
    let final_weights = transactional_bouncer.clone().abort();
    assert!(final_weights.available_capacity == initial_bouncer_weights);

    // Test transactional bouncer commit.
    let final_weights = transactional_bouncer.commit();
    assert!(final_weights.available_capacity == weights_to_commit);
}

#[test]
fn test_update_capcity() {
    let state = &mut test_state(&BlockContext::create_for_account_testing().chain_info, 0, &[]);
    let mut transactional_state = CachedState::create_transactional(state);

    let execution_summary = ExecutionSummary { ..Default::default() };
    let bouncer = Bouncer {
        available_capacity: BouncerWeights {
            builtin_count: BuiltinCount {
                bitwise: 10,
                ecdsa: 10,
                ec_op: 10,
                keccak: 0,
                pedersen: 10,
                poseidon: 10,
                range_check: 10,
            },
            gas: 10,
            message_segment_length: 10,
            n_steps: 10,
            n_events: 10,
            state_diff_size: 10,
        },
        block_contains_keccak: false,
        ..Default::default()
    };
    let mut transactional_bouncer = bouncer.create_transactional();

    let block_max_capacity = BouncerWeights {
        builtin_count: BuiltinCount {
            bitwise: 20,
            ecdsa: 20,
            ec_op: 20,
            keccak: 0,
            pedersen: 20,
            poseidon: 20,
            range_check: 20,
        },
        gas: 20,
        message_segment_length: 20,
        n_steps: 20,
        n_events: 20,
        state_diff_size: 20,
    };
    let mut block_max_capacity_with_keccak = block_max_capacity;
    block_max_capacity_with_keccak.builtin_count.keccak = 1;

    let mut bouncer_config = BouncerConfig { block_max_capacity, block_max_capacity_with_keccak };

    let mut bouncer_resources: HashMap<String, usize> = HashMap::new();
    bouncer_resources.insert(BuiltinName::bitwise.name().to_string(), 1);
    bouncer_resources.insert(BuiltinName::ecdsa.name().to_string(), 1);
    bouncer_resources.insert(BuiltinName::ec_op.name().to_string(), 1);
    // Keccak is 0 since it has special handling which will be tested separately.
    bouncer_resources.insert(BuiltinName::keccak.name().to_string(), 0);
    bouncer_resources.insert(BuiltinName::pedersen.name().to_string(), 1);
    bouncer_resources.insert(BuiltinName::poseidon.name().to_string(), 1);
    bouncer_resources.insert(BuiltinName::range_check.name().to_string(), 1);
    bouncer_resources.insert(constants::BLOB_GAS_USAGE.to_string(), 1);
    bouncer_resources.insert(constants::L1_GAS_USAGE.to_string(), 1);
    bouncer_resources.insert(constants::N_STEPS_RESOURCE.to_string(), 1);
    bouncer_resources.insert(constants::N_MEMORY_HOLES.to_string(), 1);
    let mut bouncer_resources = ResourcesMapping(bouncer_resources);

    // Test for success.
    let result = transactional_bouncer.update_available_capacity(
        &bouncer_config,
        &mut transactional_state,
        &execution_summary,
        &bouncer_resources,
        None,
    );
    assert_matches!(result, Ok(()));

    // Test for BlockFull error.
    bouncer_resources.0.insert(BuiltinName::bitwise.name().to_string(), 10);
    let result = transactional_bouncer.update_available_capacity(
        &bouncer_config,
        &mut transactional_state,
        &execution_summary,
        &bouncer_resources,
        None,
    );
    assert_matches!(
        result,
        Err(TransactionExecutorError::TransactionExecutionError(
            TransactionExecutionError::BlockFull
        ))
    );

    // Test for TxTooLarge error.
    bouncer_resources.0.insert(BuiltinName::bitwise.name().to_string(), 21);
    let result = transactional_bouncer.update_available_capacity(
        &bouncer_config,
        &mut transactional_state,
        &execution_summary,
        &bouncer_resources,
        None,
    );
    assert_matches!(
        result,
        Err(TransactionExecutorError::TransactionExecutionError(
            TransactionExecutionError::TxTooLarge
        ))
    );
    bouncer_resources.0.insert(BuiltinName::bitwise.name().to_string(), 1);

    // Test a transaction with keccak.
    bouncer_resources.0.insert(BuiltinName::keccak.name().to_string(), 1);
    let result = transactional_bouncer.update_available_capacity(
        &bouncer_config,
        &mut transactional_state,
        &execution_summary,
        &bouncer_resources,
        None,
    );
    assert_matches!(result, Ok(()));

    // Test for BlockFull error with keccak, transaction weights exceeds limit.
    let result = transactional_bouncer.update_available_capacity(
        &bouncer_config,
        &mut transactional_state,
        &execution_summary,
        &bouncer_resources,
        None,
    );
    assert_matches!(
        result,
        Err(TransactionExecutorError::TransactionExecutionError(
            TransactionExecutionError::BlockFull
        ))
    );

    // Test for BlockFull error with keccak, keccak_max_capacity is too low.
    let bouncer = Bouncer {
        available_capacity: BouncerWeights {
            builtin_count: BuiltinCount {
                bitwise: 5,
                ecdsa: 10,
                ec_op: 10,
                keccak: 0,
                pedersen: 10,
                poseidon: 10,
                range_check: 10,
            },
            gas: 10,
            message_segment_length: 10,
            n_steps: 10,
            n_events: 10,
            state_diff_size: 10,
        },
        block_contains_keccak: true,
        ..Default::default()
    };
    let mut transactional_bouncer = bouncer.create_transactional();
    // Reduce the max capacity of bitwise for keccak, so the already used bitwise will not fit in
    // the block once the capacity is updated with keccak.
    bouncer_config.block_max_capacity_with_keccak.builtin_count.bitwise = 10;
    // There is one keccak usage so this resource should fit into a keccak block.
    bouncer_resources.0.insert(BuiltinName::keccak.name().to_string(), 1);
    let result = transactional_bouncer.update_available_capacity(
        &bouncer_config,
        &mut transactional_state,
        &execution_summary,
        &bouncer_resources,
        None,
    );
    assert_matches!(
        result,
        Err(TransactionExecutorError::TransactionExecutionError(
            TransactionExecutionError::BlockFull
        ))
    );
}
