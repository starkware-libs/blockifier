use num_bigint::{BigInt, Sign};
use once_cell::sync::Lazy;
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::hash::{pedersen_hash_array, StarkFelt};
use starknet_api::transaction::Calldata;
use starknet_api::StarknetApiError;

use crate::execution::constants::L2_ADDRESS_UPPER_BOUND;
use crate::execution::execution_utils::{bigint_to_felt, felt_to_bigint};

#[cfg(test)]
#[path = "contract_address_test.rs"]
pub mod test;

pub static CONTRACT_ADDRESS_PREFIX: Lazy<BigInt> =
    Lazy::new(|| BigInt::from_bytes_be(Sign::Plus, "STARKNET_CONTRACT_ADDRESS".as_bytes()));

// TODO(Noa, 30/12/22): Add a hash_function as a parameter
pub fn calculate_contract_address(
    salt: StarkFelt,
    class_hash: ClassHash,
    constructor_calldata: &Calldata,
    deployer_address: ContractAddress,
) -> Result<ContractAddress, StarknetApiError> {
    let constructor_calldata_hash = pedersen_hash_array(&constructor_calldata.0);
    let raw_address = pedersen_hash_array(&[
        // TODO(Noa, 30/01/23): Remove unwrap when implementing a conversion from ConversionError
        // to StarknetApiError.
        bigint_to_felt(&CONTRACT_ADDRESS_PREFIX).unwrap(),
        *deployer_address.0.key(),
        salt,
        class_hash.0,
        constructor_calldata_hash,
    ]);
    // TODO(Noa, 30/01/23): Remove unwrap when implementing a conversion from ConversionError to
    // StarknetApiError.
    let mod_raw_address =
        bigint_to_felt(&(felt_to_bigint(raw_address) % &(*L2_ADDRESS_UPPER_BOUND))).unwrap();

    ContractAddress::try_from(mod_raw_address)
}
