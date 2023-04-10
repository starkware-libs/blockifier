use std::collections::HashMap;
use std::fs;
use std::iter::zip;
use std::sync::Arc;

use once_cell::sync::Lazy;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{
    calculate_contract_address, ChainId, ClassHash, ContractAddress, EntryPointSelector, Nonce,
    PatriciaKey,
};
use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass, EntryPointType,
};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransactionV0V1, DeployAccountTransaction, Fee,
    InvokeTransactionV1, TransactionSignature, TransactionVersion,
};
use starknet_api::{calldata, patricia_key, stark_felt};

use crate::abi::abi_utils::get_storage_var_address;
use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{
    CallEntryPoint, CallExecution, CallInfo, CallType, EntryPointExecutionResult, ExecutionContext,
    ExecutionResources, Retdata,
};
use crate::state::cached_state::{CachedState, ContractStorageKey};
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader, StateResult};
use crate::transaction::objects::{AccountTransactionContext, TransactionExecutionInfo};

// Addresses.
pub const TEST_CONTRACT_ADDRESS: &str = "0x100";
pub const TEST_ACCOUNT_CONTRACT_ADDRESS: &str = "0x101";
pub const TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS: &str = "0x102";
pub const TEST_SEQUENCER_ADDRESS: &str = "0x1000";
pub const TEST_ERC20_CONTRACT_ADDRESS: &str = "0x1001";

// Class hashes.
pub const TEST_CLASS_HASH: &str = "0x110";
pub const TEST_ACCOUNT_CONTRACT_CLASS_HASH: &str = "0x111";
pub const TEST_EMPTY_CONTRACT_CLASS_HASH: &str = "0x112";
pub const TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH: &str = "0x113";
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
pub const TEST_FAULTY_ACCOUNT_CONTRACT_PATH: &str =
    "./feature_contracts/compiled/account_faulty_compiled.json";
pub const ERC20_CONTRACT_PATH: &str =
    "./ERC20_without_some_syscalls/ERC20/erc20_contract_without_some_syscalls_compiled.json";

// Storage keys.
pub static TEST_ERC20_SEQUENCER_BALANCE_KEY: Lazy<StorageKey> = Lazy::new(|| {
    get_storage_var_address("ERC20_balances", &[stark_felt!(TEST_SEQUENCER_ADDRESS)]).unwrap()
});
pub static TEST_ERC20_ACCOUNT_BALANCE_KEY: Lazy<StorageKey> = Lazy::new(|| {
    get_storage_var_address("ERC20_balances", &[stark_felt!(TEST_ACCOUNT_CONTRACT_ADDRESS)])
        .unwrap()
});
pub static TEST_ERC20_FAULTY_ACCOUNT_BALANCE_KEY: Lazy<StorageKey> = Lazy::new(|| {
    get_storage_var_address("ERC20_balances", &[stark_felt!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS)])
        .unwrap()
});

pub const DEFAULT_GAS_PRICE: u128 = 100 * u128::pow(10, 9); // Given in units of wei.

/// A simple implementation of `StateReader` using `HashMap`s as storage.
#[derive(Debug, Default)]
pub struct DictStateReader {
    pub storage_view: HashMap<ContractStorageKey, StarkFelt>,
    pub address_to_nonce: HashMap<ContractAddress, Nonce>,
    pub address_to_class_hash: HashMap<ContractAddress, ClassHash>,
    pub class_hash_to_class: HashMap<ClassHash, ContractClass>,
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

    fn get_contract_class(&mut self, class_hash: &ClassHash) -> StateResult<Arc<ContractClass>> {
        let contract_class = self.class_hash_to_class.get(class_hash).cloned();
        match contract_class {
            Some(contract_class) => Ok(Arc::from(contract_class)),
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
    let raw_contract = fs::read_to_string(contract_path).unwrap();
    serde_json::from_str(&raw_contract).unwrap()
}

pub fn get_deprecated_contract_class(contract_path: &str) -> DeprecatedContractClass {
    let contract = fs::read_to_string(contract_path).unwrap();
    let mut raw_contract_class: serde_json::Value = serde_json::from_str(&contract).unwrap();

    // ABI is not required for execution.
    raw_contract_class
        .as_object_mut()
        .expect("A compiled contract must be a JSON object.")
        .remove("abi");

    serde_json::from_value(raw_contract_class).unwrap()
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
        call_type: CallType::Call,
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
        self.execute(
            state,
            &mut ExecutionResources::default(),
            &mut ExecutionContext::default(),
            &BlockContext::create_for_testing(),
            &AccountTransactionContext::default(),
        )
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
            gas_price: DEFAULT_GAS_PRICE,
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
    signature: Option<TransactionSignature>,
) -> InvokeTransactionV1 {
    InvokeTransactionV1 {
        max_fee,
        sender_address,
        calldata,
        signature: signature.unwrap_or_default(),
        ..Default::default()
    }
}

pub fn declare_tx(
    class_hash: &str,
    sender_address: ContractAddress,
    max_fee: Fee,
) -> DeclareTransactionV0V1 {
    DeclareTransactionV0V1 {
        max_fee,
        class_hash: ClassHash(stark_felt!(class_hash)),
        sender_address,
        ..Default::default()
    }
}

// Validations

pub fn compare_optional_call_infos(actual: Option<CallInfo>, expected: Option<CallInfo>) {
    match (&actual, &expected) {
        (Some(actual), Some(expected)) => compare_call_info_fields(actual, expected),
        (None, None) => (),
        _ => panic!(
            "The actual call info does not equal the expected call info. Expected: {expected:?}, \
             Actual: {actual:?}"
        ),
    }
}

pub fn compare_call_info_fields(actual: &CallInfo, expected: &CallInfo) {
    // Check selected members
    assert_eq!(actual.call, expected.call);
    assert_eq!(actual.execution, expected.execution);
    assert_eq!(actual.inner_calls.len(), expected.inner_calls.len());
    for (actual_inner_call, expected_inner_call) in zip(&actual.inner_calls, &expected.inner_calls)
    {
        compare_call_info_fields(actual_inner_call, expected_inner_call);
    }
}

pub fn validate_tx_execution_info(
    actual: TransactionExecutionInfo,
    expected: TransactionExecutionInfo,
) {
    compare_optional_call_infos(actual.validate_call_info, expected.validate_call_info);
    compare_optional_call_infos(actual.execute_call_info, expected.execute_call_info);
    compare_optional_call_infos(actual.fee_transfer_call_info, expected.fee_transfer_call_info);
    assert_eq!(actual.actual_fee, expected.actual_fee);
    assert_eq!(actual.actual_resources, expected.actual_resources);
    assert_eq!(actual.n_storage_updates, expected.n_storage_updates);
    assert_eq!(actual.n_modified_contracts, expected.n_modified_contracts);
    assert_eq!(actual.n_class_updates, expected.n_class_updates);
}
