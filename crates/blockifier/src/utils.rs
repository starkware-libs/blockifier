use std::collections::HashMap;

use num_traits::CheckedDiv;

use crate::transaction::errors::NumericError;

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

pub fn checked_div<T>(numerator: T, denominator: T) -> Result<T, NumericError>
where
    T: CheckedDiv + std::fmt::Debug,
{
    numerator.checked_div(&denominator).ok_or_else(|| NumericError::CheckedDiv {
        numerator: format!("{numerator:?}"),
        denominator: format!("{denominator:?}"),
    })
}

pub fn checked_div_f64(numerator: f64, denominator: f64) -> Result<f64, NumericError> {
    let result = numerator / denominator;
    if result.is_nan() || result.is_infinite() {
        return Err(NumericError::CheckedDivF64 { numerator, denominator });
    }
    Ok(result)
}
