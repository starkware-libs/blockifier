use std::collections::HashMap;
use std::convert::TryFrom;

use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::{get_contract_class, DictStateReader};
use starknet_api::core::ClassHash;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;

pub const TOKEN_FOR_TESTING_CLASS_HASH: &str = "0x30";
// This package is run within the StarkWare repository build directory.
pub const TOKEN_FOR_TESTING_CONTRACT_PATH: &str =
    "./src/starkware/starknet/core/test_contract/starknet_compiled_contracts_lib/starkware/\
     starknet/core/test_contract/token_for_testing.json";

pub fn create_py_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = HashMap::from([(
        ClassHash(stark_felt!(TOKEN_FOR_TESTING_CLASS_HASH)),
        get_contract_class(TOKEN_FOR_TESTING_CONTRACT_PATH),
    )]);
    CachedState::new(DictStateReader { class_hash_to_class, ..Default::default() })
}
