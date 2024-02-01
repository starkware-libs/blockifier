use std::ops::Sub;

use serde::Deserialize;

#[cfg(test)]
#[path = "bouncer_test.rs"]
mod test;

pub trait CheckedSub: Sized + Sub<Self, Output = Self> {
    fn checked_sub(&self, v: &Self) -> Option<Self>;
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, derive_more::Sub)]
/// Counted weights of the execution of transactions in a block.
/// These weights are limited by the block's maximum weights.
pub struct BouncerWeights {
    gas: u64,
    n_steps: u64,
    message_segment_length: u64,
    state_diff_size: u64,
    builtin_count: BuiltinCount,
}

impl CheckedSub for BouncerWeights {
    fn checked_sub(&self, v: &Self) -> Option<Self> {
        Some(BouncerWeights {
            gas: self.gas.checked_sub(v.gas)?,
            n_steps: self.n_steps.checked_sub(v.n_steps)?,
            message_segment_length: self
                .message_segment_length
                .checked_sub(v.message_segment_length)?,
            state_diff_size: self.state_diff_size.checked_sub(v.state_diff_size)?,
            builtin_count: self.builtin_count.checked_sub(&v.builtin_count)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, derive_more::Sub)]
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

impl CheckedSub for BuiltinCount {
    fn checked_sub(&self, v: &Self) -> Option<Self> {
        Some(BuiltinCount {
            bitwise: self.bitwise.checked_sub(v.bitwise)?,
            ecdsa: self.ecdsa.checked_sub(v.ecdsa)?,
            ec_op: self.ec_op.checked_sub(v.ec_op)?,
            keccak: self.keccak.checked_sub(v.keccak)?,
            output: self.output.checked_sub(v.output)?,
            pedersen: self.pedersen.checked_sub(v.pedersen)?,
            poseidon: self.poseidon.checked_sub(v.poseidon)?,
            range_check: self.range_check.checked_sub(v.range_check)?,
        })
    }
}
