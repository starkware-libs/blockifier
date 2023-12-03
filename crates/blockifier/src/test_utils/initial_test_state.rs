use std::collections::HashMap;

use memoize::memoize;
use starknet_api::class_hash;
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::hash::StarkHash;

use crate::execution::contract_class::ContractClassV0;
use crate::state::cached_state::CachedState;
use crate::test_utils::contracts::FeatureContractId;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::{CairoVersion, ERC20_CONTRACT_PATH, TEST_ERC20_CONTRACT_CLASS_HASH};

/// Creates a state with all feature contracts declared and deployed, two fee tokens deployed and
/// funds the validation-free account with both tokens.
#[cfg_attr(any(feature = "testing", test), memoize)]
pub fn full_test_state(
    fee_token_address: ContractAddress,
    deprecated_fee_token_address: ContractAddress,
) -> CachedState<DictStateReader> {
    // Declare an account and a token.
    let account_contract = FeatureContractId::AccountWithoutValidations;
    let cairo_version = CairoVersion::Cairo0;
    let test_erc20_class_hash = class_hash!(TEST_ERC20_CONTRACT_CLASS_HASH);
    let class_hash_to_class = HashMap::from([
        (account_contract.get_class_hash(cairo_version), account_contract.get_class(cairo_version)),
        (test_erc20_class_hash, ContractClassV0::from_file(ERC20_CONTRACT_PATH).into()),
    ]);

    // "Deploy" the erc20 contracts.
    let test_strk_address = fee_token_address;
    let test_eth_address = deprecated_fee_token_address;
    let address_to_class_hash = HashMap::from([
        (test_eth_address, test_erc20_class_hash),
        (test_strk_address, test_erc20_class_hash),
    ]);

    CachedState::from(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        ..Default::default()
    })
}
