use std::ops::Sub;

use crate::bouncer::{Bouncer, BouncerWeights, BuiltinCount};

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
/// Test the commit and abort methods of the transactional bouncer.
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

    let bouncer = Bouncer::new(initial_bouncer_weights);
    let mut transactional_bouncer = bouncer.create_transactional();
    *transactional_bouncer.capacity() = weights_to_commit;

    // Test transactional bouncer abort
    let final_weights = transactional_bouncer.clone().abort();
    assert!(final_weights.capacity == initial_bouncer_weights);

    // Test transactional bouncer commit
    let final_weights = transactional_bouncer.commit();
    assert!(final_weights.capacity == weights_to_commit);
}
