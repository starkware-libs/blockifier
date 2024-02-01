use test_case::test_case;

use super::BouncerResult;
use crate::bouncer::counting_bouncer::{Bouncer, BouncerWeights};
use crate::bouncer::errors::BouncerError;
use crate::versioned_constants::VersionedConstants;

#[test_case (
    vec![2, 5, 10],
    vec![3, 5, 5],
    vec![5, 10, 15],
    Ok(());
    "Positive flow"
)]
#[test_case (
    vec![5, 10, 15],
    vec![1, 2, 16],
    vec![6, 12, 31],
    Err(BouncerError::BatchFull {
        accumulated_weights: BouncerWeights {
            gas: 6,
            n_steps: 12,
            n_steps_with_keccak: 0,
            message_segment_length: 31,
            state_diff_size: 0,
            state_diff_size_with_kzg: 0
        },
        max_weights: BouncerWeights {
            gas: 10,
            n_steps: 20,
            n_steps_with_keccak: 0,
            message_segment_length: 30,
            state_diff_size: 0,
            state_diff_size_with_kzg: 0
        }
    });
    "Batch full"
)]
#[test_case (
    vec![1, 1, 1],
    vec![1, 21, 1],
    vec![1, 1, 1],
    Err(BouncerError::TransactionBiggerThanBatch {
        tx_weights : BouncerWeights {
            gas: 1,
            n_steps: 21,
            n_steps_with_keccak: 0,
            message_segment_length: 1,
            state_diff_size: 0,
            state_diff_size_with_kzg: 0
        },
        max_weights: BouncerWeights {
            gas: 10,
            n_steps: 20,
            n_steps_with_keccak: 0,
            message_segment_length: 30,
            state_diff_size: 0,
            state_diff_size_with_kzg: 0
        }
    });
    "Transaction bigger than batch"
)]
fn test_bouncer_add(
    first_input_weights: Vec<u64>,
    second_input_weights: Vec<u64>,
    final_weights: Vec<u64>,
    expected_result: BouncerResult<()>,
) {
    // Create a versioned constants object with test max weights
    let mut versioned_constants = VersionedConstants::latest_constants().clone();
    let max_block_weights = BouncerWeights {
        gas: 10,
        n_steps: 20,
        n_steps_with_keccak: 0,
        message_segment_length: 30,
        state_diff_size: 0,
        state_diff_size_with_kzg: 0,
    };
    versioned_constants.bouncer.max_weights = max_block_weights;

    let bouncer_weights1 = BouncerWeights {
        gas: first_input_weights[0],
        n_steps: first_input_weights[1],
        n_steps_with_keccak: 0,
        message_segment_length: first_input_weights[2],
        state_diff_size: 0,
        state_diff_size_with_kzg: 0,
    };
    let bouncer_weights2 = BouncerWeights {
        gas: second_input_weights[0],
        n_steps: second_input_weights[1],
        n_steps_with_keccak: 0,
        message_segment_length: second_input_weights[2],
        state_diff_size: 0,
        state_diff_size_with_kzg: 0,
    };
    let mut bouncer = Bouncer::default();

    bouncer.add_tx(bouncer_weights1, 0, &versioned_constants).unwrap();
    let result = bouncer.add_tx(bouncer_weights2, 0, &versioned_constants);

    // Check the return value
    if let Err(error) = result {
        assert_eq!(error.to_string(), expected_result.unwrap_err().to_string());
    } else {
        assert!(result.is_ok());
    }
    // Check the accumulated weights
    assert_eq!(bouncer.accumulated_block_weights.gas, final_weights[0]);
    assert_eq!(bouncer.accumulated_block_weights.n_steps, final_weights[1]);
    assert_eq!(bouncer.accumulated_block_weights.message_segment_length, final_weights[2]);
}
