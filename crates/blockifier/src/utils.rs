use std::collections::HashMap;

use crate::transaction::errors::NumericConversionError;

#[cfg(test)]
#[path = "utils_test.rs"]
pub mod test;
pub const STRICT_SUBTRACT_MAPPING_ERROR: &str = "lhs keys are not a subset of rhs keys";
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

// Returns a `HashMap` containing key-value pairs from `a` that are not included in `b` (if
/// a key appears in `b` with a different value, it will be part of the output)
/// if lhs keys arent a subset of rhs keys the function returns an error.
/// Usage: Get updated items from a mapping.
pub fn strict_subtract_mappings<K, V>(lhs: &HashMap<K, V>, rhs: &HashMap<K, V>) -> HashMap<K, V>
where
    K: Clone + Eq + std::hash::Hash,
    V: Clone + PartialEq,
{
    lhs.iter()
        .filter(|(k, v)| rhs.get(k).expect(STRICT_SUBTRACT_MAPPING_ERROR) != *v)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Returns the max value of two constants, at compile time.
pub const fn const_max(a: u128, b: u128) -> u128 {
    #[allow(clippy::as_conversions)]
    [a, b][(a < b) as usize]
}

/// Conversion from u128 to usize. This conversion should only be used if the value came from a
/// usize.
pub fn usize_from_u128(val: u128) -> Result<usize, NumericConversionError> {
    val.try_into().map_err(|_| NumericConversionError::U128ToUsizeError(val))
}

/// Conversion from usize to u128. May fail on architectures with over 128 bits
/// of address space.
pub fn u128_from_usize(val: usize) -> u128 {
    val.try_into().expect("Conversion from usize to u128 should not fail.")
}
