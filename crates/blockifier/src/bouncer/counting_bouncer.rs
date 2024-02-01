use std::collections::HashMap;

use strum_macros::Display;

use super::errors::BouncerError;

#[cfg(test)]
#[path = "bouncer_test.rs"]
mod test;

pub type BouncerResult<T> = Result<T, BouncerError>;

#[derive(Eq, PartialEq, Hash, Clone, Display)]
pub enum BouncerWeights {
    GasWeight,
    MessageSegmentLength,
    NSteps,
    NStepsWithKeccak, // TODO: how to handle Keccak?
    StateDiffSize,
    StateDiffSizeWithKzg,
}

#[allow(dead_code)]
pub struct Bouncer {
    pub max_block_weights: HashMap<BouncerWeights, u64>,
    pub accumulated_block_weights: HashMap<BouncerWeights, u64>,
    pub max_tx_lifespan: u64,
    pub minimum_tx_creation_time: Option<u64>,
    // TODO creation_time: u64,
}

#[allow(dead_code)]
impl Bouncer {
    // TODO: take the max_bloxk_weights and max_tx_lifespan from the config
    pub fn new(
        max_block_weights: HashMap<BouncerWeights, u64>,
        max_tx_lifespan: u64,
    ) -> BouncerResult<Self> {
        Ok(Bouncer {
            max_block_weights,
            accumulated_block_weights: HashMap::new(),
            max_tx_lifespan,
            minimum_tx_creation_time: None,
            // TODO creation_time:
            // SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
        })
    }

    pub fn add(
        &mut self,
        weights: HashMap<BouncerWeights, u64>,
        tx_time_created: u64,
    ) -> BouncerResult<()> {
        // Check that the transaction weights fit into the batch
        for (key, weight) in weights.iter() {
            assert!(
                self.max_block_weights.contains_key(key),
                "Key {} was not found in max_block_weights",
                key
            );
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
                        tx_weight: *weight,
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
