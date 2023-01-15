use cairo_felt::{Felt, FeltOps};
use sha3::{Digest, Keccak256};
use starknet_api::core::EntryPointSelector;
use starknet_api::hash::StarkHash;

use crate::abi::constants::{
    DEFAULT_ENTRY_POINT_NAME, DEFAULT_ENTRY_POINT_SELECTOR, DEFAULT_L1_ENTRY_POINT_NAME,
};
use crate::execution::execution_utils::felt_to_stark_felt;

#[cfg(test)]
#[path = "abi_utils_test.rs"]
mod test;

// TODO(Adi, 10/12/2022): Move this implementation to the starknet_api repository and use it in the
// Cairo compiler repository as well.
/// A variant of eth-keccak that computes a value that fits in a StarkNet field element.
pub fn starknet_keccak(data: &[u8]) -> Felt {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let mut result = hasher.finalize();

    // Truncate result to 250 bits.
    *result.first_mut().unwrap() &= 3;
    Felt::from_bytes_be(&result)
}

/// Returns an entry point selector, given its name.
pub fn get_selector_from_name(entry_point_name: &str) -> EntryPointSelector {
    static DEFAULT_ENTRY_POINTS: [&str; 2] =
        [DEFAULT_ENTRY_POINT_NAME, DEFAULT_L1_ENTRY_POINT_NAME];

    // The default entry points selector is not being mapped in the usual way in order to save
    // computations in the OS, and to avoid encoding the default entry point names there.
    if DEFAULT_ENTRY_POINTS.contains(&entry_point_name) {
        EntryPointSelector(StarkHash::from(DEFAULT_ENTRY_POINT_SELECTOR))
    } else {
        // TODO(Adi, 01/01/2023): Remove unwrap and forward an ABI error.
        EntryPointSelector(felt_to_stark_felt(&starknet_keccak(entry_point_name.as_bytes())))
    }
}
