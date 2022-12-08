use num_bigint::BigUint;
use sha3::{Digest, Keccak256};

use crate::abi::constants::{
    DEFAULT_ENTRY_POINT_NAME, DEFAULT_ENTRY_POINT_SELECTOR, DEFAULT_L1_ENTRY_POINT_NAME,
};

#[cfg(test)]
#[path = "abi_utils_test.rs"]
mod test;

// TODO(Adi, 10/12/2022): Move this implementation to the starknet_api repository and use it in the
// Cairo compiler repository as well.
/// A variant of eth-keccak that computes a value that fits in a StarkNet field element.
pub fn starknet_keccak(data: &[u8]) -> BigUint {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let mut result = hasher.finalize();

    // Truncate result to 250 bits.
    *result.first_mut().unwrap() &= 3;
    BigUint::from_bytes_be(&result)
}

/// Returns an entrypoint selector, given its name.
pub fn get_selector_from_name(entrypoint_name: &str) -> BigUint {
    static DEFAULT_ENTRY_POINTS: [&str; 2] =
        [DEFAULT_ENTRY_POINT_NAME, DEFAULT_L1_ENTRY_POINT_NAME];

    if DEFAULT_ENTRY_POINTS.contains(&entrypoint_name) {
        BigUint::from(DEFAULT_ENTRY_POINT_SELECTOR)
    } else {
        starknet_keccak(entrypoint_name.as_bytes())
    }
}
