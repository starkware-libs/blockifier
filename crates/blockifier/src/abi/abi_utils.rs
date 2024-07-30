use sha3::{Digest, Keccak256};
use starknet_api::core::{
    ContractAddress, EntryPointSelector, PatriciaKey, L2_ADDRESS_UPPER_BOUND,
};
use starknet_api::state::StorageKey;
use starknet_types_core::felt::{Felt, NonZeroFelt};
use starknet_types_core::hash::{Pedersen, StarkHash};

use crate::abi::constants;

#[cfg(test)]
#[path = "abi_utils_test.rs"]
mod test;

/// A variant of eth-keccak that computes a value that fits in a Starknet field element.
pub fn starknet_keccak(data: &[u8]) -> Felt {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let mut result: [u8; 32] = hasher.finalize().into();

    // Truncate result to 250 bits.
    *result.first_mut().unwrap() &= 3;
    Felt::from_bytes_be(&result)
}

/// Returns an entry point selector, given its name.
pub fn selector_from_name(entry_point_name: &str) -> EntryPointSelector {
    static DEFAULT_ENTRY_POINTS: [&str; 2] =
        [constants::DEFAULT_ENTRY_POINT_NAME, constants::DEFAULT_L1_ENTRY_POINT_NAME];

    // The default entry points selector is not being mapped in the usual way in order to save
    // computations in the OS, and to avoid encoding the default entry point names there.
    if DEFAULT_ENTRY_POINTS.contains(&entry_point_name) {
        EntryPointSelector(Felt::from(constants::DEFAULT_ENTRY_POINT_SELECTOR))
    } else {
        EntryPointSelector(starknet_keccak(entry_point_name.as_bytes()))
    }
}

/// Returns the storage address of a Starknet storage variable given its name and arguments.
pub fn get_storage_var_address(storage_var_name: &str, args: &[Felt]) -> StorageKey {
    let storage_var_name_hash = starknet_keccak(storage_var_name.as_bytes());

    let storage_key_hash =
        args.iter().fold(storage_var_name_hash, |res, arg| Pedersen::hash(&res, arg));

    let storage_key = storage_key_hash
        .mod_floor(&NonZeroFelt::from_raw(Felt::from(*L2_ADDRESS_UPPER_BOUND).to_raw()));

    StorageKey(
        PatriciaKey::try_from(storage_key)
            .expect("Should be within bounds as retrieved mod L2_ADDRESS_UPPER_BOUND."),
    )
}

/// Returns the storage key inside the fee token corresponding to the first storage cell where the
/// balance of contract_address is stored. Note that the reference implementation of an ERC20 stores
/// the balance in two consecutive storage cells.
pub fn get_fee_token_var_address(contract_address: ContractAddress) -> StorageKey {
    get_storage_var_address("ERC20_balances", &[*contract_address.0.key()])
}
