use std::collections::HashMap;
use std::hash::Hash;
use std::num::TryFromIntError;
use std::ops::{Add, AddAssign};

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

pub fn merge_hashmaps<K, V>(x: &HashMap<K, V>, y: &HashMap<K, V>) -> HashMap<K, V>
where
    K: Hash + Eq + Clone,
    V: Add<Output = V> + AddAssign + Default + Clone,
{
    let mut result = x.clone();
    for (key, value) in y {
        result
            .entry(key.clone())
            .and_modify(|v| v.add_assign(value.clone()))
            .or_insert(value.clone());
    }
    result
}

/// Conversion from usize to u128. Currently, usize has 64 bits, so this conversion should never
/// fail.
pub fn usize_from_u128(val: u128) -> Result<usize, TryFromIntError> {
    val.try_into()
}

/// Conversion from u128 to usize. This conversion should only be used if the value came from a
/// usize.
pub fn u128_from_usize(val: usize) -> Result<u128, TryFromIntError> {
    val.try_into()
}
