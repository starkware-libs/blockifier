use serde::Deserialize;

#[cfg(test)]
#[path = "bouncer_test.rs"]
mod test;

macro_rules! checked_sub_struct {
    ($self:expr, $other:expr, $( $field:ident ),*) => {
        Some(Self {
            $(
                $field: $self.$field.checked_sub($other.$field)?,
            )*
        })
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
    fn checked_sub(self, other: Self) -> Option<Self> {
        checked_sub_struct!(
            self,
            other,
            gas,
            n_steps,
            message_segment_length,
            state_diff_size,
            builtin_count
        )
    }
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
    fn checked_sub(self, v: Self) -> Option<Self> {
        checked_sub_struct!(
            self,
            v,
            bitwise,
            ecdsa,
            ec_op,
            keccak,
            output,
            pedersen,
            poseidon,
            range_check
        )
    }
}
