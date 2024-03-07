use std::collections::{HashMap, HashSet};

use assert_matches::assert_matches;
use cairo_vm::serde::deserialize_program::BuiltinName;
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use super::BouncerConfig;
use crate::abi::constants;
use crate::blockifier::transaction_executor::TransactionExecutorError;
use crate::bouncer::{Bouncer, BouncerWeights, BuiltinCount};
use crate::context::BlockContext;
use crate::execution::call_info::ExecutionSummary;
use crate::state::cached_state::{CachedState, StateChangesKeys};
use crate::test_utils::initial_test_state::test_state;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::ResourcesMapping;

#[test]
fn test_bouncer_exeecds() {
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

    assert!(!bouncer_weights.exceeds(&max_bouncer_weights));

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

    assert!(bouncer_weights_exceeds_max.exceeds(&max_bouncer_weights));
}

#[test]
fn test_bouncer_merge() {
    let initial_bouncer = Bouncer {
        executed_class_hashes: HashSet::from([ClassHash(StarkFelt::from(0_u128))]),
        visited_storage_entries: HashSet::from([(
            ContractAddress::from(0_u128),
            StorageKey::from(0_u128),
        )]),
        state_changes_keys: StateChangesKeys::default(),
        bouncer_config: BouncerConfig::default(),
        accumulated_capacity: BouncerWeights {
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
        },
    };

    let execution_summary_to_merge = ExecutionSummary {
        executed_class_hashes: HashSet::from([
            ClassHash(StarkFelt::from(1_u128)),
            ClassHash(StarkFelt::from(2_u128)),
        ]),
        visited_storage_entries: HashSet::from([
            (ContractAddress::from(1_u128), StorageKey::from(1_u128)),
            (ContractAddress::from(2_u128), StorageKey::from(2_u128)),
        ]),
        ..Default::default()
    };

    let weights_to_merge = BouncerWeights {
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

    // TODO (yael): test also state_changes_keys merge with real values.
    let state_changes_keys_to_merge = StateChangesKeys::default();

    let mut merged_bouncer = initial_bouncer.clone();
    merged_bouncer.merge(
        weights_to_merge,
        &execution_summary_to_merge,
        &state_changes_keys_to_merge,
    );

    assert_eq!(
        merged_bouncer.accumulated_capacity,
        initial_bouncer.accumulated_capacity + weights_to_merge
    );
    assert_eq!(
        merged_bouncer.executed_class_hashes,
        HashSet::from([
            ClassHash(StarkFelt::from(0_u128)),
            ClassHash(StarkFelt::from(1_u128)),
            ClassHash(StarkFelt::from(2_u128))
        ])
    );

    assert_eq!(
        merged_bouncer.visited_storage_entries,
        HashSet::from([
            (ContractAddress::from(0_u128), StorageKey::from(0_u128)),
            (ContractAddress::from(1_u128), StorageKey::from(1_u128)),
            (ContractAddress::from(2_u128), StorageKey::from(2_u128))
        ])
    );
}

#[test]
fn test_update_capcity() {
    let state = &mut test_state(&BlockContext::create_for_account_testing().chain_info, 0, &[]);
    let mut transactional_state = CachedState::create_transactional(state);

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
    let bouncer_config = BouncerConfig { block_max_capacity, block_max_capacity_with_keccak };

    let execution_summary = ExecutionSummary { ..Default::default() };
    let mut bouncer = Bouncer {
        accumulated_capacity: BouncerWeights {
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
        bouncer_config,
        ..Default::default()
    };

    let bouncer_resources: HashMap<String, usize> = HashMap::from([
        (BuiltinName::bitwise.name().to_string(), 1),
        (BuiltinName::ecdsa.name().to_string(), 1),
        (BuiltinName::ec_op.name().to_string(), 1),
        // Keccak is 0 since it has special handling, which will be tested separately.
        (BuiltinName::keccak.name().to_string(), 0),
        (BuiltinName::pedersen.name().to_string(), 1),
        (BuiltinName::poseidon.name().to_string(), 1),
        (BuiltinName::range_check.name().to_string(), 1),
        (constants::BLOB_GAS_USAGE.to_string(), 1),
        (constants::L1_GAS_USAGE.to_string(), 1),
        (constants::N_STEPS_RESOURCE.to_string(), 1),
        (constants::N_MEMORY_HOLES.to_string(), 1),
    ]);
    let mut bouncer_resources = ResourcesMapping(bouncer_resources);

    // Test for success.
    let result = bouncer.update_inner(
        &mut transactional_state,
        &execution_summary,
        &bouncer_resources,
        None,
    );
    assert_matches!(result, Ok(()));

    // Test for BlockFull error.
    bouncer_resources.0.insert(BuiltinName::bitwise.name().to_string(), 10);
    let result = bouncer.update_inner(
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
    let result = bouncer.update_inner(
        &mut transactional_state,
        &execution_summary,
        &bouncer_resources,
        None,
    );
    assert_matches!(
        result,
        Err(TransactionExecutorError::TransactionExecutionError(
            TransactionExecutionError::TransactionTooLarge
        ))
    );
    bouncer_resources.0.insert(BuiltinName::bitwise.name().to_string(), 1);

    // Test a transaction with keccak.
    bouncer_resources.0.insert(BuiltinName::keccak.name().to_string(), 1);
    let result = bouncer.update_inner(
        &mut transactional_state,
        &execution_summary,
        &bouncer_resources,
        None,
    );
    assert_matches!(result, Ok(()));

    // Test for BlockFull error with keccak.
    let result = bouncer.update_inner(
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
