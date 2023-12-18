use std::collections::HashMap;

use cairo_felt::Felt252;
use num_integer::Integer;
use sha3::{Digest, Keccak256};
use starknet_api::core::{ContractAddress, EntryPointSelector, L2_ADDRESS_UPPER_BOUND};
use starknet_api::hash::{pedersen_hash, StarkFelt, StarkHash};
use starknet_api::state::StorageKey;

use super::constants::CONSTRUCTOR_ENTRY_POINT_NAME;
use crate::abi::constants;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::transaction::constants::{
    EXECUTE_ENTRY_POINT_NAME, TRANSFER_ENTRY_POINT_NAME, VALIDATE_DECLARE_ENTRY_POINT_NAME,
    VALIDATE_DEPLOY_ENTRY_POINT_NAME, VALIDATE_ENTRY_POINT_NAME,
};

#[cfg(test)]
#[path = "abi_utils_test.rs"]
mod test;

/// A variant of eth-keccak that computes a value that fits in a Starknet field element.
pub fn starknet_keccak(data: &[u8]) -> Felt252 {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let mut result = hasher.finalize();

    // Truncate result to 250 bits.
    *result.first_mut().unwrap() &= 3;
    Felt252::from_bytes_be(&result)
}

/// Returns an entry point selector, given its name.
pub fn selector_from_name(entry_point_name: &str) -> EntryPointSelector {
    static DEFAULT_ENTRY_POINTS: [&str; 2] =
        [constants::DEFAULT_ENTRY_POINT_NAME, constants::DEFAULT_L1_ENTRY_POINT_NAME];

    // The default entry points selector is not being mapped in the usual way in order to save
    // computations in the OS, and to avoid encoding the default entry point names there.
    if DEFAULT_ENTRY_POINTS.contains(&entry_point_name) {
        EntryPointSelector(StarkHash::from(constants::DEFAULT_ENTRY_POINT_SELECTOR))
    } else {
        EntryPointSelector(felt_to_stark_felt(&starknet_keccak(entry_point_name.as_bytes())))
    }
}

pub fn selector_to_name(entry_point_selector: StarkFelt) -> String {
    static SELECTOR_MAP: once_cell::sync::Lazy<HashMap<StarkFelt, &'static str>> =
        once_cell::sync::Lazy::new(|| {
            let array = [
                (selector_from_name(CONSTRUCTOR_ENTRY_POINT_NAME).0, CONSTRUCTOR_ENTRY_POINT_NAME),
                (selector_from_name(EXECUTE_ENTRY_POINT_NAME).0, EXECUTE_ENTRY_POINT_NAME),
                (selector_from_name(TRANSFER_ENTRY_POINT_NAME).0, TRANSFER_ENTRY_POINT_NAME),
                (selector_from_name(VALIDATE_ENTRY_POINT_NAME).0, VALIDATE_ENTRY_POINT_NAME),
                (
                    selector_from_name(VALIDATE_DECLARE_ENTRY_POINT_NAME).0,
                    VALIDATE_DECLARE_ENTRY_POINT_NAME,
                ),
                (
                    selector_from_name(VALIDATE_DEPLOY_ENTRY_POINT_NAME).0,
                    VALIDATE_DEPLOY_ENTRY_POINT_NAME,
                ),
            ];

            array.iter().cloned().collect()
        });

    SELECTOR_MAP
        .get(&entry_point_selector)
        .map(|&name| name.to_string())
        .unwrap_or_else(|| panic!("{} is not defined.", entry_point_selector))
}

/// Returns the storage address of a Starknet storage variable given its name and arguments.
pub fn get_storage_var_address(storage_var_name: &str, args: &[StarkFelt]) -> StorageKey {
    let storage_var_name_hash = starknet_keccak(storage_var_name.as_bytes());
    let storage_var_name_hash = felt_to_stark_felt(&storage_var_name_hash);

    let storage_key_hash =
        args.iter().fold(storage_var_name_hash, |res, arg| pedersen_hash(&res, arg));

    let storage_key = stark_felt_to_felt(storage_key_hash)
        .mod_floor(&Felt252::from_bytes_be(&L2_ADDRESS_UPPER_BOUND.to_bytes_be()));

    StorageKey::try_from(felt_to_stark_felt(&storage_key))
        .expect("Should be within bounds as retrieved mod L2_ADDRESS_UPPER_BOUND.")
}

/// Returns the storage key inside the fee token corresponding to the first storage cell where the
/// balance of contract_address is stored. Note that the reference implementation of an ERC20 stores
/// the balance in two consecutive storage cells.
pub fn get_fee_token_var_address(contract_address: &ContractAddress) -> StorageKey {
    get_storage_var_address("ERC20_balances", &[*contract_address.0.key()])
}
