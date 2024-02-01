use std::collections::HashMap;

use test_case::test_case;

use super::BouncerResult;
use crate::bouncer::counting_bouncer::{Bouncer, BouncerWeights};
use crate::bouncer::errors::BouncerError;

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
    vec![5, 10, 15],
    Err(BouncerError::BatchFull {
        parameter: BouncerWeights::NSteps.to_string(),
        tx_weight: 16,
        accumulated_weight: 15,
        max_weight: 30
    });
    "Batch full"
)]
#[test_case (
    vec![1, 1, 1],
    vec![1, 21, 1],
    vec![1, 1, 1],
    Err(BouncerError::TransactionBiggerThanBatch {
        parameter: BouncerWeights::MessageSegmentLength.to_string(),
        weight: 21,
        max: 20
    });
    "Transaction bigger than batch"
)]
fn test_bouncer_add(
    first_input_weights: Vec<u64>,
    second_input_weights: Vec<u64>,
    final_weights: Vec<u64>,
    expected_result: BouncerResult<()>,
) {
    // Create a new bouncer
    let mut max_block_weights: HashMap<BouncerWeights, u64> = HashMap::new();
    max_block_weights.insert(BouncerWeights::GasWeight, 10);
    max_block_weights.insert(BouncerWeights::MessageSegmentLength, 20);
    max_block_weights.insert(BouncerWeights::NSteps, 30);
    let mut bouncer = Bouncer::new(max_block_weights, 10).unwrap();

    // Add a 2 new transactions
    let mut weights: HashMap<BouncerWeights, u64> = HashMap::new();
    weights.insert(BouncerWeights::GasWeight, first_input_weights[0]);
    weights.insert(BouncerWeights::MessageSegmentLength, first_input_weights[1]);
    weights.insert(BouncerWeights::NSteps, first_input_weights[2]);
    let _ = bouncer.add(weights, 0);

    let mut weights: HashMap<BouncerWeights, u64> = HashMap::new();
    weights.insert(BouncerWeights::GasWeight, second_input_weights[0]);
    weights.insert(BouncerWeights::MessageSegmentLength, second_input_weights[1]);
    weights.insert(BouncerWeights::NSteps, second_input_weights[2]);
    let result = bouncer.add(weights, 0);

    // Check the return value
    if let Err(error) = result {
        assert_eq!(error.to_string(), expected_result.unwrap_err().to_string());
    } else {
        assert!(result.is_ok());
    }
    // Check the accumulated weights
    assert_eq!(
        bouncer.accumulated_block_weights.get(&BouncerWeights::GasWeight).unwrap(),
        &final_weights[0]
    );
    assert_eq!(
        bouncer.accumulated_block_weights.get(&BouncerWeights::MessageSegmentLength).unwrap(),
        &final_weights[1]
    );
    assert_eq!(
        bouncer.accumulated_block_weights.get(&BouncerWeights::NSteps).unwrap(),
        &final_weights[2]
    );
}
