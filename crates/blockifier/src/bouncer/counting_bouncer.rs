use std::ops::Add;

use serde::Deserialize;

use super::errors::BouncerError;
use crate::versioned_constants::VersionedConstants;

#[cfg(test)]
#[path = "bouncer_test.rs"]
mod test;

pub type BouncerResult<T> = Result<T, BouncerError>;

#[allow(dead_code)]
#[derive(Clone, Debug, Default, Deserialize, Copy)]
pub struct BouncerWeights {
    gas: u64,
    number_of_steps: u64,
    number_of_steps_with_keccak: u64,
    message_segment_length: u64,
    state_diff_size: u64,
    state_diff_size_with_kzg: u64,
    // TODO(yael) add more weights (n_memory_holes, builtin_steps)
    // TODO(yael) understand n_steps_with_keccak and state_diff_size_with_kzg special handling
}

impl Add for BouncerWeights {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        BouncerWeights {
            gas: self.gas + other.gas,
            number_of_steps: self.number_of_steps + other.number_of_steps,
            number_of_steps_with_keccak: self.number_of_steps_with_keccak
                + other.number_of_steps_with_keccak,
            message_segment_length: self.message_segment_length + other.message_segment_length,
            state_diff_size: self.state_diff_size + other.state_diff_size,
            state_diff_size_with_kzg: self.state_diff_size_with_kzg
                + other.state_diff_size_with_kzg,
        }
    }
}

#[allow(dead_code)]
impl BouncerWeights {
    pub fn exceeds_limit(self, versioned_constants: &VersionedConstants) -> bool {
        self.gas > versioned_constants.bouncer.max_weights.gas
            || self.number_of_steps > versioned_constants.bouncer.max_weights.number_of_steps
            || self.number_of_steps_with_keccak
                > versioned_constants.bouncer.max_weights.number_of_steps_with_keccak
            || self.message_segment_length
                > versioned_constants.bouncer.max_weights.message_segment_length
            || self.state_diff_size > versioned_constants.bouncer.max_weights.state_diff_size
            || self.state_diff_size_with_kzg
                > versioned_constants.bouncer.max_weights.state_diff_size_with_kzg
    }
}

#[allow(dead_code)]
#[derive(Default)]
pub struct Bouncer {
    pub accumulated_block_weights: BouncerWeights,
    pub minimum_tx_creation_time: Option<u64>,
    // TODO creation_time: u64,
}

#[allow(dead_code)]
impl Bouncer {
    pub fn add_tx(
        &mut self,
        weights: BouncerWeights,
        tx_time_created: u64,
        versioned_constants: &VersionedConstants,
    ) -> BouncerResult<()> {
        // Check if the transaction is too big to fit a batch
        if weights.exceeds_limit(versioned_constants) {
            return Err(BouncerError::TransactionBiggerThanBatch {
                tx_weights: weights,
                max_weights: versioned_constants.bouncer.max_weights,
            });
        }

        // Add the transaction weights to the accumulated weights
        self.accumulated_block_weights = self.accumulated_block_weights.add(weights);

        // Check if the transaction weights fit into the batch
        if self.accumulated_block_weights.exceeds_limit(versioned_constants) {
            return Err(BouncerError::BatchFull {
                accumulated_weights: self.accumulated_block_weights,
                max_weights: versioned_constants.bouncer.max_weights,
            });
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
