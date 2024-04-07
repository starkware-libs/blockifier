use std::collections::HashMap;

use crate::transaction::errors::NumericConversionError;

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

/// Returns the max value of two constants, at compile time.
pub const fn const_max(a: u128, b: u128) -> u128 {
    [a, b][(a < b) as usize]
}

/// Conversion from u128 to usize. This conversion should only be used if the value came from a
/// usize.
pub fn usize_from_u128(val: u128) -> Result<usize, NumericConversionError> {
    val.try_into().map_err(|_| NumericConversionError::U128ToUsizeError(val))
}

/// Conversion from usize to u128. May fail on architectures with over 128 bits
/// of address space.
pub fn u128_from_usize(val: usize) -> Result<u128, NumericConversionError> {
    val.try_into().map_err(|_| NumericConversionError::UsizeToU128Error(val))
}

/// Returns the ceiling of the division of two u128 numbers.
pub fn u128_div_ceil(a: u128, b: u128) -> u128 {
    let mut result = a / b;
    if result * b < a {
        result += 1;
    }
    result
}
