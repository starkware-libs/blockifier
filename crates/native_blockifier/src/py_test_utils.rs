use std::collections::HashMap;
use std::convert::TryFrom;

use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::{get_contract_class, DictStateReader};
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::{patricia_key, stark_felt};

pub const TEST_CLASS_HASH: &str = "0x30";
pub const ACCOUNT_CLASS_HASH: &str = "0x31";
pub const TEST_CONTRACT_PATH: &str = "./native_blockifier/py_feature_contracts/test_contract.cairo";
pub const ACCOUNT_CONTRACT_PATH: &str =
    "./native_blockifier/py_feature_contracts/dummy_account.cairo";
pub const TEST_CONTRACT_ADDRESS: &str = "0x64";
pub const ACCOUNT_CONTRACT_ADDRESS: &str = "0x2d2";

pub fn create_py_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = HashMap::from([
        (ClassHash(stark_felt!(TEST_CLASS_HASH)), get_contract_class(TEST_CONTRACT_PATH)),
        (ClassHash(stark_felt!(ACCOUNT_CLASS_HASH)), get_contract_class(ACCOUNT_CONTRACT_PATH)),
    ]);
    let address_to_class_hash = HashMap::from([
        (
            ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS)),
            ClassHash(stark_felt!(TEST_CLASS_HASH)),
        ),
        (
            ContractAddress(patricia_key!(ACCOUNT_CONTRACT_ADDRESS)),
            ClassHash(stark_felt!(ACCOUNT_CLASS_HASH)),
        ),
    ]);
    CachedState::new(DictStateReader {
        class_hash_to_class,
        address_to_class_hash,
        ..Default::default()
    })
}
