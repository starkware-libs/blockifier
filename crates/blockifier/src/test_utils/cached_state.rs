// REBASE NOTE: ideally this will all be deleted

use std::collections::HashMap;

use starknet_api::class_hash;
use starknet_api::core::ClassHash;
use starknet_api::hash::StarkHash;

use super::{ERC20_FULL_CONTRACT_PATH, TEST_EMPTY_CONTRACT_CAIRO1_PATH};
use crate::execution::contract_class::{ContractClassV1, NativeContractClassV1};
use crate::state::cached_state::ContractClassMapping;
use crate::test_utils::{TEST_EMPTY_CONTRACT_CLASS_HASH, TEST_ERC20_FULL_CONTRACT_CLASS_HASH};

pub fn get_erc20_class_hash_mapping() -> ContractClassMapping {
    HashMap::from([
        (
            class_hash!(TEST_ERC20_FULL_CONTRACT_CLASS_HASH),
            NativeContractClassV1::from_file(ERC20_FULL_CONTRACT_PATH).into(),
        ),
        (
            class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
            ContractClassV1::from_file(TEST_EMPTY_CONTRACT_CAIRO1_PATH).into(),
        ),
    ])
}
