use derive_more::Add;
use serde::Deserialize;

use crate::versioned_constants::VersionedConstants;

// TODO decide if a separate directory is needed for the bouncer.
#[allow(dead_code)]
#[derive(Add, Clone, Copy, Debug, Default, Deserialize)]
pub struct BouncerWeights {
    gas: u64,
    number_of_steps: u64,
    number_of_steps_with_keccak: u64,
    message_segment_length: u64,
    state_diff_size: u64,
    state_diff_size_with_kzg: u64,
    builtin_count: BuiltinCount,
    // TODO(yael) understand n_steps_with_keccak and state_diff_size_with_kzg special handling
}

#[derive(Add, Clone, Copy, Debug, Default, Deserialize)]
// TODO how to initialize the max values
pub struct BuiltinCount {
    bitwise: u64,
    ecdsa: u64,
    ec_op: u64,
    keccak: u64,
    output: u64,
    pedersen: u64,
    poseidon: u64,
    range_check: u64,
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
