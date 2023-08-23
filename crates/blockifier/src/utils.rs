use std::collections::HashMap;

use cairo_felt::Felt252;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use thiserror::Error;

#[cfg(test)]
#[path = "utils_test.rs"]
pub mod test;

/// Returns a `HashMap` containing key-value pairs from `a` that are not included in `b` (if
/// a key appears in `b` with a different value, it will be part of the output).
/// Usage: Get updated items from a mapping.
pub fn subtract_mappings<K, V>(lhs: &HashMap<K, V>, rhs: &HashMap<K, V>) -> HashMap<K, V>
where
    K: Clone + Eq + std::hash::Hash,
    V: Clone + PartialEq,
{
    lhs.iter().filter(|(k, v)| rhs.get(k) != Some(v)).map(|(k, v)| (k.clone(), v.clone())).collect()
}

#[derive(Debug, Error)]
pub enum UtilError {
    #[error("Felt {0:?} is too big to convert to u128.")]
    UnconvertibleFeltToU128(Felt252),
}

pub fn felt_to_u128(felt: &Felt252) -> Result<u128, UtilError> {
    felt.to_u128().ok_or_else(|| UtilError::UnconvertibleFeltToU128(felt.clone()))
}

pub fn two_u128_to_biguint(low: &u128, high: &u128) -> BigUint {
    (BigUint::from(*high) << 128) + BigUint::from(*low)
}
