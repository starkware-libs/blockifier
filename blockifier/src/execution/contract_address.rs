use cairo_rs::bigint;
use num_bigint::{BigInt, Sign};
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::hash::{pedersen_hash_array, StarkFelt};
use starknet_api::transaction::CallData;
use starknet_api::StarknetApiError;

use super::constants::CONTRACT_ADDRESS_BITS;
use crate::execution::execution_utils::{bigint_to_felt, felt_to_bigint};

const CONTRACT_ADDRESS_PREFIX: &str = "STARKNET_CONTRACT_ADDRESS";

// TODO(Noa, 30/12/22): Add a hash_function as a parameter
pub fn calculate_contract_address(
    salt: StarkFelt,
    class_hash: ClassHash,
    constructor_calldata: &CallData,
    deployer_address: ContractAddress,
) -> Result<ContractAddress, StarknetApiError> {
    let l2_address_upper_bound = bigint!(2).pow(CONTRACT_ADDRESS_BITS) - 256;
    let contract_address_prefix =
        BigInt::from_bytes_be(Sign::Plus, CONTRACT_ADDRESS_PREFIX.as_bytes());
    let constructor_calldata_hash = pedersen_hash_array(&constructor_calldata.0);
    let raw_address = pedersen_hash_array(&[
        // TODO(Noa, 30/01/23): Remove unwrap when bigint_to_felt won't use anyhow::Result
        bigint_to_felt(&contract_address_prefix).unwrap(),
        *deployer_address.0.key(),
        salt,
        class_hash.0,
        constructor_calldata_hash,
    ]);
    // TODO(Noa, 30/01/23): Remove unwrap when bigint_to_felt won't use anyhow::Result
    let mod_raw_address =
        bigint_to_felt(&(felt_to_bigint(raw_address) % l2_address_upper_bound)).unwrap();

    ContractAddress::try_from(mod_raw_address)
}
