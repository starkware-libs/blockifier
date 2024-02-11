use std::collections::HashMap;

use crate::bouncer::{Bouncer, BouncerError};

#[test]
fn test_bouncer_add() {
    // Create a new bouncer
    let mut max_block_weights = HashMap::new();
    max_block_weights.insert("a".to_string(), 10);
    max_block_weights.insert("b".to_string(), 20);
    max_block_weights.insert("c".to_string(), 30);
    let mut bouncer = Bouncer::new(max_block_weights, 10).unwrap();

    // Test the good flow
    let mut weights = HashMap::new();
    weights.insert("a".to_string(), 5);
    weights.insert("b".to_string(), 10);
    weights.insert("c".to_string(), 15);
    assert!(bouncer.add(weights, 0).is_ok());
    assert_eq!(bouncer.accumulated_block_weights.get("a").unwrap(), &5);
    assert_eq!(bouncer.accumulated_block_weights.get("b").unwrap(), &10);
    assert_eq!(bouncer.accumulated_block_weights.get("c").unwrap(), &15);

    // Test the case where the batch doesn't have enough space for the transaction
    let mut weights = HashMap::new();
    weights.insert("a".to_string(), 1);
    weights.insert("b".to_string(), 2);
    weights.insert("c".to_string(), 16);
    let error = bouncer.add(weights, 0).unwrap_err();
    assert_eq!(
        format!("{}", error),
        format!(
            "{}",
            BouncerError::BatchFull {
                parameter: "c".to_string(),
                weight: 16,
                accumulated_weight: 15,
                max_weight: 30
            }
        )
    );
    assert_eq!(bouncer.accumulated_block_weights.get("a").unwrap(), &5);
    assert_eq!(bouncer.accumulated_block_weights.get("b").unwrap(), &10);
    assert_eq!(bouncer.accumulated_block_weights.get("c").unwrap(), &15);

    // Test the case where the transaction is bigger than the batch
    let mut weights = HashMap::new();
    weights.insert("a".to_string(), 1);
    weights.insert("b".to_string(), 21);
    weights.insert("c".to_string(), 1);
    let error = bouncer.add(weights, 0).unwrap_err();
    assert_eq!(
        format!("{}", error),
        format!(
            "{}",
            BouncerError::TransactionBiggerThanBatch {
                parameter: "b".to_string(),
                weight: 21,
                max: 20
            }
        )
    );
    assert_eq!(bouncer.accumulated_block_weights.get("a").unwrap(), &5);
    assert_eq!(bouncer.accumulated_block_weights.get("b").unwrap(), &10);
    assert_eq!(bouncer.accumulated_block_weights.get("c").unwrap(), &15);
}

#[test]
fn test_bouncer_should_create_block() {
    let mut max_block_weights = HashMap::new();
    max_block_weights.insert("a".to_string(), 10);
    let mut bouncer = Bouncer::new(max_block_weights, 10).unwrap();
    // Test the case where the batch is empty
    assert!(!bouncer.should_create_block());
    // Test the case where max_tx_lifetime has not passed since the oldest transaction timestamp
    bouncer.batch_creation_time = 20;
    bouncer.add(HashMap::new(), 11).unwrap();
    assert!(!bouncer.should_create_block());
    // Test the case where max_tx_lifetime has passed since the oldest transaction timestamp
    bouncer.add(HashMap::new(), 2).unwrap();
    assert!(bouncer.should_create_block());
    // Test the case where the batch is full
    let mut weights = HashMap::new();
    weights.insert("a".to_string(), 10);
    bouncer.add(weights, 11).unwrap();
    let mut weights = HashMap::new();
    weights.insert("a".to_string(), 1);
    bouncer.add(weights, 11).unwrap_err();
    assert!(bouncer.should_create_block());
}
