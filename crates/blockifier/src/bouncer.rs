use std::collections::HashMap;
use std::time::SystemTime;

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
#[derive(Debug)]
pub struct Bouncer {
    max_block_weights: HashMap<String, u64>,
    accumulated_block_weights: HashMap<String, u64>,
    max_tx_lifespan: u64,
    minimum_tx_creation_time: Option<u64>,
    batch_creation_time: u64,
    batch_empty: bool,
    batch_full: bool,
}

#[allow(dead_code)]
impl Bouncer {
    fn new(max_block_weights: HashMap<String, u64>, max_tx_lifespan: u64) -> BouncerResult<Self> {
        Ok(Bouncer {
            max_block_weights,
            accumulated_block_weights: HashMap::new(),
            max_tx_lifespan,
            minimum_tx_creation_time: None,
            batch_creation_time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
            batch_empty: true,
            batch_full: false,
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
                    // TODO(Yael) - do we want to try and fit a smaller transaction into this batch?
                    self.batch_full = true;
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
        self.batch_empty = false;

        // Update the oldest transaction timestamp
        if self.minimum_tx_creation_time.is_none()
            || tx_time_created < self.minimum_tx_creation_time.unwrap()
        {
            self.minimum_tx_creation_time = Some(tx_time_created);
        }

        Ok(())
    }

    fn should_create_block(&self) -> bool {
        if self.batch_empty {
            return false;
        }

        if self.batch_full {
            log::debug!("A new block should be created because the batch is full");
            return true;
        }

        // Check if the oldest transaction in the batch is waiting for more than max_tx_lifespan
        if let Some(minimum_tx_creation_time) = self.minimum_tx_creation_time {
            if minimum_tx_creation_time + self.max_tx_lifespan < self.batch_creation_time {
                log::debug!(
                    "A new block should be created because more than max_tx_lifespan seconds have \
                     passed since oldest transaction timestamp: oldest tx has been waiting for {} \
                     seconds, the lifespan is {}.",
                    self.batch_creation_time - minimum_tx_creation_time,
                    self.max_tx_lifespan
                );
                return true;
            }
        }

        false
    }
}
