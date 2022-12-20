use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

use starknet_api::core::ClassHash;
use starknet_api::hash::StarkHash;
use starknet_api::shash;

use crate::cached_state::{CachedState, DictStateReader};
use crate::execution::contract_class::ContractClass;

pub const TEST_CONTRACT_PATH: &str = "./feature_contracts/compiled/simple_contract_compiled.json";
pub const WITHOUT_ARG_SELECTOR: &str =
    "0x382a967a31be13f23e23a5345f7a89b0362cc157d6fbe7564e6396a83cf4b4f";
pub const WITH_ARG_SELECTOR: &str =
    "0xe7def693d16806ca2a2f398d8de5951344663ba77f340ed7a958da731872fc";
pub const BITWISE_AND_SELECTOR: &str =
    "0xad451bd0dba3d8d97104e1bfc474f88605ccc7acbe1c846839a120fdf30d95";
pub const SQRT_SELECTOR: &str = "0x137a07fa9c479e27114b8ae1fbf252f2065cf91a0d8615272e060a7ccf37309";
pub const RETURN_RESULT_SELECTOR: &str =
    "0x39a1491f76903a16feed0a6433bec78de4c73194944e1118e226820ad479701";
pub const GET_VALUE_SELECTOR: &str =
    "0x26813d396fdb198e9ead934e4f7a592a8b88a059e45ab0eb6ee53494e8d45b0";
pub const TEST_LIBRARY_CALL_SELECTOR: &str =
    "0x3604cea1cdb094a73a31144f14a3e5861613c008e1e879939ebc4827d10cd50";
pub const TEST_CLASS_HASH: &str = "0x1";
pub const TEST_CONTRACT_ADDRESS: &str = "0x100";

// TODO(Adi, 10/02/2022): Replace with 'account_contract_without_validations' once the syscalls are
// implemented.
pub const ACCOUNT_CONTRACT_PATH: &str =
    "./feature_contracts/compiled/account_without_some_syscalls_compiled.json";

// TODO(Adi, 15/01/2023): Remove and compute the class hash corresponding to the ERC20 contract in
// starkgate once we use the real ERC20 contract.
pub const TEST_ERC20_CONTRACT_CLASS_HASH: &str = "0x1010";
pub const TEST_ERC20_CONTRACT_ADDRESS: &str = "0x1000";
pub const TEST_ERC20_SELF_BALANCE_KEY: &str =
    "0x723973208639b7839ce298f7ffea61e3f9533872defd7abdb91023db4658812";
pub const TEST_ERC20_ACCOUNT_BALANCE_KEY: &str =
    "0x2a2c49c4dba0d91b34f2ade85d41d09561f9a77884c15ba2ab0f2241b080deb";

// TODO(Adi, 25/12/2022): Consider removing this function once we use the starknet_api transaction
// struct instead of our own, which contains a `contract_path` instead of a `contract_address`.
pub fn get_contract_class(contract_path: &str) -> ContractClass {
    let path = PathBuf::from(contract_path);
    ContractClass::from_file(&path).expect("File must contain the content of a compiled contract.")
}

pub fn get_test_contract_class() -> ContractClass {
    get_contract_class(TEST_CONTRACT_PATH)
}

pub fn create_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class =
        HashMap::from([(ClassHash(shash!(TEST_CLASS_HASH)), Rc::new(get_test_contract_class()))]);
    CachedState::new(DictStateReader { class_hash_to_class, ..Default::default() })
}
