use std::collections::HashMap;

use num_traits::Zero;

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

pub(crate) fn check_non_zero<T>(value: T, info: &str) -> Result<(), NumericConversionError>
where
    T: Zero,
{
    if value.is_zero() {
        return Err(NumericConversionError::DivByZero { info: info.to_string() });
    }
    Ok(())
}
