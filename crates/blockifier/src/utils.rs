use std::collections::HashMap;

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

/// converts from f64 to u128, asserts no conversion error has been introduced
pub fn f64_into_u128(value: f64) -> u128 {
    let value_u128 = value as u128;
    assert_eq!(value, value_u128 as f64);
    value_u128
}

/// converts from f64 to u128, asserts no conversion error has been introduced
pub fn usize_into_f64(value: usize) -> f64 {
    let value_f64 = value as f64;
    assert_eq!(value, value_f64 as usize);
    value_f64
}

/// usize as u128
pub fn usize_as_u128(value: usize) -> u128 {
    value as u128
}
