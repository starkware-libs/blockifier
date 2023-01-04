use std::collections::HashMap;
use std::path::PathBuf;

use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::EntryPointType;
use starknet_api::transaction::Calldata;
use starknet_api::{patricia_key, stark_felt};

use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{CallEntryPoint, CallInfo, EntryPointExecutionResult};
use crate::state::cached_state::{CachedState, DictStateReader};
use crate::state::state_api::State;
use crate::transaction::objects::AccountTransactionContext;

pub const TEST_ACCOUNT_CONTRACT_ADDRESS: &str = "0x101";
// TODO(Adi, 25/12/2022): Remove once a class hash can be computed given a class.
pub const TEST_ACCOUNT_CONTRACT_CLASS_HASH: &str = "0x111";
pub const ACCOUNT_CONTRACT_PATH: &str =
    "./feature_contracts/compiled/account_without_validations_compiled.json";
pub const TEST_CONTRACT_PATH: &str = "./feature_contracts/compiled/test_contract_compiled.json";
pub const SECURITY_TEST_CONTRACT_PATH: &str =
    "./feature_contracts/compiled/security_tests_contract_compiled.json";
pub const WITHOUT_ARG_SELECTOR: &str =
    "0x382a967a31be13f23e23a5345f7a89b0362cc157d6fbe7564e6396a83cf4b4f";
pub const WITH_ARG_SELECTOR: &str =
    "0xe7def693d16806ca2a2f398d8de5951344663ba77f340ed7a958da731872fc";
pub const BITWISE_AND_SELECTOR: &str =
    "0xad451bd0dba3d8d97104e1bfc474f88605ccc7acbe1c846839a120fdf30d95";
pub const SQRT_SELECTOR: &str = "0x137a07fa9c479e27114b8ae1fbf252f2065cf91a0d8615272e060a7ccf37309";
pub const RETURN_RESULT_SELECTOR: &str =
    "0x39a1491f76903a16feed0a6433bec78de4c73194944e1118e226820ad479701";
pub const TEST_STORAGE_READ_WRITE_SELECTOR: &str =
    "0x3b097c62d3e4b85742aadd0dfb823f96134b886ec13bda57b68faf86f294d97";
pub const TEST_LIBRARY_CALL_SELECTOR: &str =
    "0x3604cea1cdb094a73a31144f14a3e5861613c008e1e879939ebc4827d10cd50";
pub const TEST_NESTED_LIBRARY_CALL_SELECTOR: &str =
    "0x3a6a8bae4c51d5959683ae246347ffdd96aa5b2bfa68cc8c3a6a7c2ed0be331";
pub const TEST_CALL_CONTRACT_SELECTOR: &str =
    "0x27c3334165536f239cfd400ed956eabff55fc60de4fb56728b6a4f6b87db01c";
pub const TEST_DEPLOY_SELECTOR: &str =
    "0x169f135eddda5ab51886052d777a57f2ea9c162d713691b5e04a6d4ed71d47f";
pub const TEST_STORAGE_VAR_SELECTOR: &str =
    "0x36fa6de2810d05c3e1a0ebe23f60b9c2f4629bbead09e5a9704e1c5632630d5";
pub const TEST_CLASS_HASH: &str = "0x110";
pub const TEST_CONTRACT_ADDRESS: &str = "0x100";

pub const TEST_SEQUENCER_ADDRESS: &str = "0x1000";

// TODO(Adi, 15/01/2023): Remove and use the ERC20 contract in starkgate once we use the real
// ERC20 contract.
pub const ERC20_CONTRACT_PATH: &str =
    "./ERC20_without_some_syscalls/ERC20/erc20_contract_without_some_syscalls_compiled.json";
// TODO(Adi, 15/01/2023): Remove and compute the class hash corresponding to the ERC20 contract in
// starkgate once we use the real ERC20 contract.
pub const TEST_ERC20_CONTRACT_CLASS_HASH: &str = "0x1010";
pub const TEST_ERC20_CONTRACT_ADDRESS: &str = "0x1001";
pub const TEST_ERC20_SEQUENCER_BALANCE_KEY: &str =
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

pub fn trivial_external_entry_point() -> CallEntryPoint {
    CallEntryPoint {
        class_hash: None,
        entry_point_type: EntryPointType::External,
        entry_point_selector: EntryPointSelector(stark_felt!(0)),
        calldata: Calldata(vec![].into()),
        storage_address: ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS)),
        caller_address: ContractAddress::default(),
    }
}

pub fn create_test_state_util(
    class_hash: &str,
    contract_path: &str,
    contract_address: &str,
) -> CachedState<DictStateReader> {
    let class_hash_to_class =
        HashMap::from([(ClassHash(stark_felt!(class_hash)), get_contract_class(contract_path))]);
    let address_to_class_hash = HashMap::from([(
        ContractAddress(patricia_key!(contract_address)),
        ClassHash(stark_felt!(class_hash)),
    )]);
    CachedState::new(DictStateReader {
        class_hash_to_class,
        address_to_class_hash,
        ..Default::default()
    })
}

pub fn create_test_state() -> CachedState<DictStateReader> {
    create_test_state_util(TEST_CLASS_HASH, TEST_CONTRACT_PATH, TEST_CONTRACT_ADDRESS)
}

pub fn create_security_test_state() -> CachedState<DictStateReader> {
    create_test_state_util(TEST_CLASS_HASH, SECURITY_TEST_CONTRACT_PATH, TEST_CONTRACT_ADDRESS)
}

impl CallEntryPoint {
    /// Executes the call directly, without account context.
    pub fn execute_directly(self, state: &mut dyn State) -> EntryPointExecutionResult<CallInfo> {
        self.execute(state, &AccountTransactionContext::default())
    }
}
