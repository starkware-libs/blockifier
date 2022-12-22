use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::CallData;
use starknet_api::StarknetApiError;

// TODO(Noa, 30/12/22): Add a hash_function as a parameter
pub fn calculate_contract_address_from_hash(
    _salt: StarkFelt,
    _class_hash: ClassHash,
    _constructor_calldata: &CallData,
    _deployer_address: &ContractAddress,
) -> Result<ContractAddress, StarknetApiError> {
    // TODO(Noa, 30/12/22):Implement using the  pedersen_hash
    ContractAddress::try_from(StarkHash::from(1))
}
