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

pub fn bit_reverse_index(x: u32, log_domain_size: u32) -> u32 {
    x.reverse_bits() >> (32 - log_domain_size)
}

pub fn bit_reverse_in_place<T: Copy>(array: &mut [T], log_domain_size: u32) {
    for i in 0..array.len() {
        array.swap(i, bit_reverse_index(i as u32, log_domain_size) as usize);
    }
}

pub fn bit_reverse_vec<T: Copy>(vec: &Vec<T>, log_domain_size: u32) -> Vec<T> {
    let mut result = vec.clone();
    bit_reverse_in_place(&mut result, log_domain_size);
    result
}
