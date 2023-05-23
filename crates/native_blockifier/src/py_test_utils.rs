use std::collections::HashMap;
use std::convert::TryFrom;

use blockifier::execution::contract_class::ContractClassV0;
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::DictStateReader;
use starknet_api::core::ClassHash;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;

pub const TOKEN_FOR_TESTING_CLASS_HASH: &str = "0x30";
pub const TOKEN_FOR_TESTING_ADDRESS: &str =
    "0x362075710386a46fab02ac1eae27c1c50f8d7df88633672bb65403f1547911d";
pub const TOKEN_FOR_TESTING_INITIAL_BALANCE: u128 = 1_000_000_000_000_000_000;
// This package is run within the StarkWare repository build directory.
pub const TOKEN_FOR_TESTING_CONTRACT_PATH: &str =
    "./src/starkware/starknet/core/test_contract/starknet_compiled_contracts_lib/starkware/\
     starknet/core/test_contract/token_for_testing.json";

pub fn create_py_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = HashMap::from([(
        ClassHash(stark_felt!(TOKEN_FOR_TESTING_CLASS_HASH)),
        ContractClassV0::from_file(TOKEN_FOR_TESTING_CONTRACT_PATH).into(),
    )]);
    CachedState::new(DictStateReader { class_hash_to_class, ..Default::default() })
}
