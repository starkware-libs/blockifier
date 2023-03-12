use std::collections::HashMap;
use std::path::PathBuf;

use once_cell::sync::Lazy;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{
    calculate_contract_address, ChainId, ClassHash, ContractAddress, EntryPointSelector, Nonce,
    PatriciaKey,
};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::{EntryPointType, StorageKey};
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransaction, DeployAccountTransaction, Fee,
    InvokeTransaction, TransactionVersion,
};
use starknet_api::{calldata, patricia_key, stark_felt};

use crate::abi::abi_utils::get_storage_var_address;
use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{
    CallEntryPoint, CallExecution, CallInfo, EntryPointExecutionResult, ExecutionContext,
    ExecutionResources, Retdata,
};
use crate::state::cached_state::{CachedState, ContractClassMapping, ContractStorageKey};
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader, StateResult};
use crate::transaction::objects::AccountTransactionContext;

// Addresses.
pub const TEST_ACCOUNT_CONTRACT_ADDRESS: &str = "0x101";
pub const TEST_CONTRACT_ADDRESS: &str = "0x100";
pub const TEST_SEQUENCER_ADDRESS: &str = "0x1000";
pub const TEST_ERC20_CONTRACT_ADDRESS: &str = "0x1001";

// Class hashes.
pub const TEST_CLASS_HASH: &str = "0x110";
pub const TEST_ACCOUNT_CONTRACT_CLASS_HASH: &str = "0x111";
pub const TEST_EMPTY_CONTRACT_CLASS_HASH: &str = "0x112";
// TODO(Adi, 15/01/2023): Remove and compute the class hash corresponding to the ERC20 contract in
// starkgate once we use the real ERC20 contract.
pub const TEST_ERC20_CONTRACT_CLASS_HASH: &str = "0x1010";

// Paths.
pub const ACCOUNT_CONTRACT_PATH: &str =
    "./feature_contracts/compiled/account_without_validations_compiled.json";
pub const TEST_CONTRACT_PATH: &str = "./feature_contracts/compiled/test_contract_compiled.json";
pub const SECURITY_TEST_CONTRACT_PATH: &str =
    "./feature_contracts/compiled/security_tests_contract_compiled.json";
pub const TEST_EMPTY_CONTRACT_PATH: &str =
    "./feature_contracts/compiled/empty_contract_compiled.json";
pub const ERC20_CONTRACT_PATH: &str =
    "./ERC20_without_some_syscalls/ERC20/erc20_contract_without_some_syscalls_compiled.json";

// Selectors.
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

// Storage keys.
pub static TEST_ERC20_SEQUENCER_BALANCE_KEY: Lazy<StorageKey> = Lazy::new(|| {
    get_storage_var_address("ERC20_balances", &[stark_felt!(TEST_SEQUENCER_ADDRESS)]).unwrap()
});
pub static TEST_ERC20_ACCOUNT_BALANCE_KEY: Lazy<StorageKey> = Lazy::new(|| {
    get_storage_var_address("ERC20_balances", &[stark_felt!(TEST_ACCOUNT_CONTRACT_ADDRESS)])
        .unwrap()
});

/// A simple implementation of `StateReader` using `HashMap`s as storage.
#[derive(Debug, Default)]
pub struct DictStateReader {
    pub storage_view: HashMap<ContractStorageKey, StarkFelt>,
    pub address_to_nonce: HashMap<ContractAddress, Nonce>,
    pub address_to_class_hash: HashMap<ContractAddress, ClassHash>,
    pub class_hash_to_class: ContractClassMapping,
}

impl StateReader for DictStateReader {
    fn get_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        let contract_storage_key = (contract_address, key);
        let value = self.storage_view.get(&contract_storage_key).copied().unwrap_or_default();
        Ok(value)
    }

    fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce> {
        let nonce = self.address_to_nonce.get(&contract_address).copied().unwrap_or_default();
        Ok(nonce)
    }

    fn get_contract_class(&mut self, class_hash: &ClassHash) -> StateResult<ContractClass> {
        let contract_class = self.class_hash_to_class.get(class_hash).cloned();
        match contract_class {
            Some(contract_class) => Ok(contract_class),
            None => Err(StateError::UndeclaredClassHash(*class_hash)),
        }
    }

    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        let class_hash =
            self.address_to_class_hash.get(&contract_address).copied().unwrap_or_default();
        Ok(class_hash)
    }
}

pub fn get_contract_class(contract_path: &str) -> ContractClass {
    let path = PathBuf::from(contract_path);
    ContractClass::try_from(path).expect("File must contain the content of a compiled contract.")
}

pub fn get_test_contract_class() -> ContractClass {
    get_contract_class(TEST_CONTRACT_PATH)
}

pub fn trivial_external_entry_point() -> CallEntryPoint {
    CallEntryPoint {
        class_hash: None,
        entry_point_type: EntryPointType::External,
        entry_point_selector: EntryPointSelector(stark_felt!(0)),
        calldata: calldata![],
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

pub fn create_deploy_test_state() -> CachedState<DictStateReader> {
    let class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    let empty_contract_class_hash = ClassHash(stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH));
    let contract_address = ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS));
    let another_contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &calldata![
            stark_felt!(3), // Calldata: address.
            stark_felt!(3)  // Calldata: value.
        ],
        ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS)),
    )
    .unwrap();
    let class_hash_to_class = HashMap::from([
        (class_hash, get_contract_class(TEST_CONTRACT_PATH)),
        (empty_contract_class_hash, get_contract_class(TEST_EMPTY_CONTRACT_PATH)),
    ]);
    let address_to_class_hash =
        HashMap::from([(contract_address, class_hash), (another_contract_address, class_hash)]);
    CachedState::new(DictStateReader {
        class_hash_to_class,
        address_to_class_hash,
        ..Default::default()
    })
}

impl CallEntryPoint {
    // Executes the call directly, without account context.
    pub fn execute_directly(self, state: &mut dyn State) -> EntryPointExecutionResult<CallInfo> {
        self.execute(&mut ExecutionContext::new(
            state,
            &mut ExecutionResources::default(),
            &BlockContext::create_for_testing(),
            &AccountTransactionContext::default(),
        ))
    }
}

impl BlockContext {
    pub fn create_for_testing() -> BlockContext {
        BlockContext {
            chain_id: ChainId("SN_GOERLI".to_string()),
            block_number: BlockNumber::default(),
            block_timestamp: BlockTimestamp::default(),
            sequencer_address: ContractAddress(patricia_key!(TEST_SEQUENCER_ADDRESS)),
            fee_token_address: ContractAddress(patricia_key!(TEST_ERC20_CONTRACT_ADDRESS)),
            cairo_resource_fee_weights: HashMap::default(),
            invoke_tx_max_n_steps: 1_000_000,
            validate_max_n_steps: 1_000_000,
        }
    }
}

impl CallExecution {
    pub fn from_retdata(retdata: Retdata) -> Self {
        Self { retdata, ..Default::default() }
    }
}

// Transactions.
pub fn deploy_account_tx(class_hash: &str, max_fee: Fee) -> DeployAccountTransaction {
    let class_hash = ClassHash(stark_felt!(class_hash));
    let deployer_address = ContractAddress::default();
    let contract_address_salt = ContractAddressSalt::default();
    let contract_address = calculate_contract_address(
        contract_address_salt,
        class_hash,
        &calldata![],
        deployer_address,
    )
    .unwrap();

    DeployAccountTransaction {
        max_fee,
        version: TransactionVersion(stark_felt!(1)),
        class_hash,
        contract_address,
        contract_address_salt,
        ..Default::default()
    }
}

pub fn invoke_tx(
    calldata: Calldata,
    sender_address: ContractAddress,
    max_fee: Fee,
) -> InvokeTransaction {
    InvokeTransaction {
        max_fee,
        version: TransactionVersion(stark_felt!(1)),
        sender_address,
        calldata,
        ..Default::default()
    }
}

pub fn declare_tx(
    class_hash: &str,
    sender_address: ContractAddress,
    max_fee: Fee,
) -> DeclareTransaction {
    DeclareTransaction {
        max_fee,
        version: TransactionVersion(StarkFelt::from(1)),
        class_hash: ClassHash(stark_felt!(class_hash)),
        sender_address,
        ..Default::default()
    }
}
