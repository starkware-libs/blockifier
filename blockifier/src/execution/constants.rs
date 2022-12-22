use cairo_rs::bigint;
use num_bigint::BigInt;
use once_cell::sync::Lazy;

pub const FIELD_SIZE_BITS: u32 = 251;
pub const CONTRACT_ADDRESS_BITS: u32 = FIELD_SIZE_BITS;

pub static L2_ADDRESS_UPPER_BOUND: Lazy<BigInt> =
    Lazy::new(|| bigint!(2).pow(CONTRACT_ADDRESS_BITS) - 256);
