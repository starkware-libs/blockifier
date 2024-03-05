use std::ops::Sub;

use crate::blockifier::block::BouncerConfig;
use crate::bouncer::{Bouncer, BouncerWeights, BuiltinCount};

#[test]
fn test_block_weights_sub_checked() {
    let max_bouncer_weights = BouncerWeights {
        gas: 10,
        n_steps: 10,
        n_events: 10,
        message_segment_length: 10,
        state_diff_size: 10,
        builtin_count: BuiltinCount {
            bitwise: 10,
            ecdsa: 10,
            ec_op: 10,
            keccak: 10,
            pedersen: 10,
            poseidon: 10,
            range_check: 10,
        },
    };

    let bouncer_weights = BouncerWeights {
        gas: 7,
        n_steps: 0,
        n_events: 0,
        message_segment_length: 10,
        state_diff_size: 7,
        builtin_count: BuiltinCount {
            bitwise: 6,
            ecdsa: 7,
            ec_op: 7,
            keccak: 8,
            pedersen: 7,
            poseidon: 9,
            range_check: 10,
        },
    };

    let result = max_bouncer_weights.checked_sub(bouncer_weights).unwrap();
    let difference_bouncer_weights = max_bouncer_weights.sub(bouncer_weights);
    assert_eq!(result, difference_bouncer_weights);

    let bouncer_weights_exceeds_max = BouncerWeights {
        gas: 5,
        n_steps: 5,
        n_events: 5,
        message_segment_length: 5,
        state_diff_size: 5,
        builtin_count: BuiltinCount {
            bitwise: 11,
            ecdsa: 5,
            ec_op: 5,
            keccak: 5,
            pedersen: 5,
            poseidon: 5,
            range_check: 5,
        },
    };

    let result = max_bouncer_weights.checked_sub(bouncer_weights_exceeds_max);
    assert!(result.is_none());
}

#[test]
fn test_tansactional_bouncer() {
    let max_bouncer_weights = BouncerWeights {
        gas: 10,
        n_steps: 10,
        n_events: 10,
        message_segment_length: 10,
        state_diff_size: 10,
        builtin_count: BuiltinCount {
            bitwise: 10,
            ecdsa: 10,
            ec_op: 10,
            keccak: 10,
            pedersen: 10,
            poseidon: 10,
            range_check: 10,
        },
    };

    let tx_weights = BouncerWeights {
        gas: 7,
        n_steps: 0,
        n_events: 0,
        message_segment_length: 10,
        state_diff_size: 7,
        builtin_count: BuiltinCount {
            bitwise: 6,
            ecdsa: 7,
            ec_op: 7,
            keccak: 8,
            pedersen: 7,
            poseidon: 9,
            range_check: 10,
        },
    };

    let bouncer_config = BouncerConfig {
        block_max_capacity: max_bouncer_weights,
        block_max_capacity_with_keccak: max_bouncer_weights,
    };

    let mut bouncer = Bouncer::new_block_bouncer(bouncer_config);
    let mut transactional_bouncer = bouncer.create_transactional();
    transactional_bouncer.transactional.available_capacity =
        transactional_bouncer.transactional.available_capacity.checked_sub(tx_weights).unwrap();

    // Test transactional bouncer abort
    let parent = transactional_bouncer.abort();
    assert!(parent.available_capacity == max_bouncer_weights);

    // Test transactional bouncer commit
    let parent = transactional_bouncer.commit();
    let expected_capacity = max_bouncer_weights.sub(tx_weights);
    assert!(parent.available_capacity == expected_capacity);
}
