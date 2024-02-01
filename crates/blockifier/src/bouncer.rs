use std::collections::HashMap;

use thiserror::Error;

#[cfg(test)]
#[path = "bouncer_test.rs"]
mod test;

#[derive(Debug, Error)]
pub enum BouncerError {
    #[error(
        "The batch remaining capapcity is too small for the transaction. parameter {}, weight {}, \
         accumulated_weight {}, max_weight {}",
        parameter,
        weight,
        accumulated_weight,
        max_weight
    )]
    BatchFull { parameter: String, weight: u64, accumulated_weight: u64, max_weight: u64 },
    #[error(transparent)]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error(
        "Transaction is too big to fit the batch, parameter {} weight {} is bigger than the \
         upper_bound {}",
        parameter,
        weight,
        max
    )]
    TransactionBiggerThanBatch { parameter: String, weight: u64, max: u64 },
}

pub type BouncerResult<T> = Result<T, BouncerError>;

#[allow(dead_code)]
pub struct Bouncer {
    max_block_weights: HashMap<String, u64>,
    accumulated_block_weights: HashMap<String, u64>,
    max_tx_lifespan: u64,
    minimum_tx_creation_time: Option<u64>,
    // TODO creation_time: u64,
}

#[allow(dead_code)]
impl Bouncer {
    fn new(max_block_weights: HashMap<String, u64>, max_tx_lifespan: u64) -> BouncerResult<Self> {
        Ok(Bouncer {
            max_block_weights,
            accumulated_block_weights: HashMap::new(),
            max_tx_lifespan,
            minimum_tx_creation_time: None,
            // TODO creation_time:
            // SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
        })
    }

    fn add(&mut self, weights: HashMap<String, u64>, tx_time_created: u64) -> BouncerResult<()> {
        // Check that the transaction weights fit into the batch
        for (key, weight) in weights.iter() {
            if !self.max_block_weights.contains_key(key) {
                continue;
            }
            let max_weight = self.max_block_weights.get(key).unwrap();
            if max_weight < weight {
                return Err(BouncerError::TransactionBiggerThanBatch {
                    parameter: key.to_string(),
                    weight: *weight,
                    max: *max_weight,
                });
            } else {
                let accumulated_weight_entry =
                    self.accumulated_block_weights.entry(key.clone()).or_insert(0);
                if *accumulated_weight_entry + weight > *max_weight {
                    return Err(BouncerError::BatchFull {
                        parameter: key.to_string(),
                        weight: *weight,
                        accumulated_weight: *accumulated_weight_entry,
                        max_weight: *max_weight,
                    });
                }
            }
        }

        // Update the accumulated block weights
        for (key, weight) in weights.iter() {
            let _ = self
                .accumulated_block_weights
                .entry(key.clone())
                .and_modify(|accumulated_weight| *accumulated_weight += weight);
        }

        // Update the oldest transaction timestamp
        if self.minimum_tx_creation_time.is_none()
            || tx_time_created < self.minimum_tx_creation_time.unwrap()
        {
            self.minimum_tx_creation_time = Some(tx_time_created);
        }

        Ok(())
    }
}
