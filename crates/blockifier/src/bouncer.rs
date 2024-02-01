use serde::Deserialize;

#[cfg(test)]
#[path = "bouncer_test.rs"]
mod test;

macro_rules! generate_checked_sub_function {
    ($($field:ident),+) => {
        fn checked_sub(self: Self, other: Self) -> Option<Self> {
            Some(
                Self {
                    $(
                        $field: self.$field.checked_sub(other.$field)?,
                    )+
                }
            )
        }
    };
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default, derive_more::Sub, Deserialize, PartialEq)]
/// Counted weights of the execution of transactions in a block.
/// These weights are limited by the block's maximum weights.
pub struct BouncerWeights {
    gas: u64,
    n_steps: u64,
    message_segment_length: u64,
    state_diff_size: u64,
    builtin_count: BuiltinCount,
}

#[allow(dead_code)]
impl BouncerWeights {
    generate_checked_sub_function!(
        gas,
        n_steps,
        message_segment_length,
        state_diff_size,
        builtin_count
    );
}

#[derive(Clone, Copy, Debug, Default, derive_more::Sub, Deserialize, PartialEq)]
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

impl BuiltinCount {
    generate_checked_sub_function!(
        bitwise,
        ecdsa,
        ec_op,
        keccak,
        output,
        pedersen,
        poseidon,
        range_check
    );
}
