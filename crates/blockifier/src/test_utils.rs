pub mod cached_state;
pub mod contracts;
pub mod declare;
pub mod deploy_account;
pub mod dict_state_reader;
pub mod initial_test_state;
pub mod invoke;
pub mod prices;
pub mod struct_impls;

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use cairo_felt::Felt252;
use num_traits::{One, Zero};
use starknet_api::core::{ContractAddress, EntryPointSelector, Nonce, PatriciaKey};
use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass, EntryPointType,
};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, Resource, ResourceBounds, ResourceBoundsMapping,
};
use starknet_api::{calldata, contract_address, patricia_key, stark_felt};

use crate::abi::abi_utils::{get_fee_token_var_address, selector_from_name};
use crate::abi::constants::{self};
use crate::execution::contract_class::{ContractClass, ContractClassV0};
use crate::execution::entry_point::{CallEntryPoint, CallType};
use crate::execution::execution_utils::felt_to_stark_felt;
<<<<<<< HEAD
||||||| e3ccd803
use crate::state::cached_state::{CachedState, ContractClassMapping, ContractStorageKey};
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader, StateResult};
use crate::transaction::constants::EXECUTE_ENTRY_POINT_NAME;
use crate::transaction::objects::{AccountTransactionContext, DeprecatedAccountTransactionContext};
use crate::transaction::transactions::{DeployAccountTransaction, InvokeTransaction};
=======
use crate::state::cached_state::{CachedState, ContractClassMapping, StorageEntry};
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader, StateResult};
use crate::transaction::constants::EXECUTE_ENTRY_POINT_NAME;
use crate::transaction::objects::{AccountTransactionContext, DeprecatedAccountTransactionContext};
use crate::transaction::transactions::{DeployAccountTransaction, InvokeTransaction};
>>>>>>> origin/main-v0.13.0
use crate::utils::const_max;

// TODO(Dori, 1/2/2024): Remove these constants once all tests use the `contracts` and
//   `initial_test_state` modules for testing.
// Addresses.
pub const TEST_CONTRACT_ADDRESS: &str = "0x100";
pub const TEST_CONTRACT_ADDRESS_2: &str = "0x200";
pub const SECURITY_TEST_CONTRACT_ADDRESS: &str = "0x300";
pub const LEGACY_TEST_CONTRACT_ADDRESS: &str = "0x400";
pub const TEST_ACCOUNT_CONTRACT_ADDRESS: &str = "0x101";
pub const TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS: &str = "0x102";
pub const TEST_SEQUENCER_ADDRESS: &str = "0x1000";
pub const TEST_ERC20_CONTRACT_ADDRESS: &str = "0x1001";
pub const TEST_ERC20_CONTRACT_ADDRESS2: &str = "0x1002";

// Class hashes.
pub const TEST_CLASS_HASH: &str = "0x110";
pub const TEST_ACCOUNT_CONTRACT_CLASS_HASH: &str = "0x111";
pub const TEST_EMPTY_CONTRACT_CLASS_HASH: &str = "0x112";
pub const TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH: &str = "0x113";
pub const SECURITY_TEST_CLASS_HASH: &str = "0x114";
pub const TEST_GRINDY_ACCOUNT_CONTRACT_CLASS_HASH_CAIRO0: &str = "0x115";
pub const TEST_GRINDY_ACCOUNT_CONTRACT_CLASS_HASH_CAIRO1: &str = "0x116";
pub const LEGACY_TEST_CLASS_HASH: &str = "0x117";
// TODO(Adi, 15/01/2023): Remove and compute the class hash corresponding to the ERC20 contract in
// starkgate once we use the real ERC20 contract.
pub const TEST_ERC20_CONTRACT_CLASS_HASH: &str = "0x1010";

// Paths.
pub const ACCOUNT_CONTRACT_CAIRO1_PATH: &str =
    "./feature_contracts/cairo1/compiled/account_with_dummy_validate.casm.json";
pub const ACCOUNT_CONTRACT_CAIRO0_PATH: &str =
    "./feature_contracts/cairo0/compiled/account_with_dummy_validate_compiled.json";
pub const GRINDY_ACCOUNT_CONTRACT_CAIRO0_PATH: &str =
    "./feature_contracts/cairo0/compiled/account_with_long_validate_compiled.json";
pub const GRINDY_ACCOUNT_CONTRACT_CAIRO1_PATH: &str =
    "./feature_contracts/cairo1/compiled/account_with_long_validate.casm.json";
pub const TEST_CONTRACT_CAIRO0_PATH: &str =
    "./feature_contracts/cairo0/compiled/test_contract_compiled.json";
pub const TEST_CONTRACT_CAIRO1_PATH: &str =
    "./feature_contracts/cairo1/compiled/test_contract.casm.json";
pub const LEGACY_TEST_CONTRACT_CAIRO1_PATH: &str =
    "./feature_contracts/cairo1/compiled/legacy_test_contract.casm.json";
pub const SECURITY_TEST_CONTRACT_CAIRO0_PATH: &str =
    "./feature_contracts/cairo0/compiled/security_tests_contract_compiled.json";
pub const TEST_EMPTY_CONTRACT_CAIRO0_PATH: &str =
    "./feature_contracts/cairo0/compiled/empty_contract_compiled.json";
pub const TEST_EMPTY_CONTRACT_CAIRO1_PATH: &str =
    "./feature_contracts/cairo1/compiled/empty_contract.casm.json";
pub const TEST_FAULTY_ACCOUNT_CONTRACT_CAIRO0_PATH: &str =
    "./feature_contracts/cairo0/compiled/account_faulty_compiled.json";
pub const ERC20_CONTRACT_PATH: &str =
    "./ERC20_without_some_syscalls/ERC20/erc20_contract_without_some_syscalls_compiled.json";

#[derive(Clone, Copy, Debug)]
pub enum CairoVersion {
    Cairo0,
    Cairo1,
}

impl Default for CairoVersion {
    fn default() -> Self {
        Self::Cairo0
    }
}

// Storage keys.
pub fn test_erc20_sequencer_balance_key() -> StorageKey {
    get_fee_token_var_address(&contract_address!(TEST_SEQUENCER_ADDRESS))
}
pub fn test_erc20_account_balance_key() -> StorageKey {
    get_fee_token_var_address(&contract_address!(TEST_ACCOUNT_CONTRACT_ADDRESS))
}
pub fn test_erc20_faulty_account_balance_key() -> StorageKey {
    get_fee_token_var_address(&contract_address!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS))
}

// The max_fee / resource bounds used for txs in this test.
pub const MAX_L1_GAS_AMOUNT: u64 = 1000000;
pub const MAX_L1_GAS_PRICE: u128 = DEFAULT_STRK_L1_GAS_PRICE;
pub const MAX_RESOURCE_COMMITMENT: u128 = MAX_L1_GAS_AMOUNT as u128 * MAX_L1_GAS_PRICE;
pub const MAX_FEE: u128 = MAX_L1_GAS_AMOUNT as u128 * DEFAULT_ETH_L1_GAS_PRICE;

// The amount of test-token allocated to the account in this test, set to a multiple of the max
// amount deprecated / non-deprecated transactions commit to paying.
pub const BALANCE: u128 = 10 * const_max(MAX_FEE, MAX_RESOURCE_COMMITMENT);

pub const DEFAULT_ETH_L1_GAS_PRICE: u128 = 100 * u128::pow(10, 9); // Given in units of Wei.
pub const DEFAULT_STRK_L1_GAS_PRICE: u128 = 100 * u128::pow(10, 9); // Given in units of STRK.

// The block number of the BlockContext being used for testing.
pub const CURRENT_BLOCK_NUMBER: u64 = 2000;

// The block timestamp of the BlockContext being used for testing.
pub const CURRENT_BLOCK_TIMESTAMP: u64 = 1072023;

pub const CHAIN_ID_NAME: &str = "SN_GOERLI";

<<<<<<< HEAD
||||||| e3ccd803
/// A simple implementation of `StateReader` using `HashMap`s as storage.
#[derive(Debug, Default)]
pub struct DictStateReader {
    pub storage_view: HashMap<ContractStorageKey, StarkFelt>,
    pub address_to_nonce: HashMap<ContractAddress, Nonce>,
    pub address_to_class_hash: HashMap<ContractAddress, ClassHash>,
    pub class_hash_to_class: HashMap<ClassHash, ContractClass>,
    pub class_hash_to_compiled_class_hash: HashMap<ClassHash, CompiledClassHash>,
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

    fn get_compiled_contract_class(
        &mut self,
        class_hash: &ClassHash,
    ) -> StateResult<ContractClass> {
        let contract_class = self.class_hash_to_class.get(class_hash).cloned();
        match contract_class {
            Some(contract_class) => Ok(contract_class),
            _ => Err(StateError::UndeclaredClassHash(*class_hash)),
        }
    }

    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        let class_hash =
            self.address_to_class_hash.get(&contract_address).copied().unwrap_or_default();
        Ok(class_hash)
    }

    fn get_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
    ) -> StateResult<starknet_api::core::CompiledClassHash> {
        let compiled_class_hash =
            self.class_hash_to_compiled_class_hash.get(&class_hash).copied().unwrap_or_default();
        Ok(compiled_class_hash)
    }
}

=======
/// A simple implementation of `StateReader` using `HashMap`s as storage.
#[derive(Debug, Default)]
pub struct DictStateReader {
    pub storage_view: HashMap<StorageEntry, StarkFelt>,
    pub address_to_nonce: HashMap<ContractAddress, Nonce>,
    pub address_to_class_hash: HashMap<ContractAddress, ClassHash>,
    pub class_hash_to_class: HashMap<ClassHash, ContractClass>,
    pub class_hash_to_compiled_class_hash: HashMap<ClassHash, CompiledClassHash>,
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

    fn get_compiled_contract_class(
        &mut self,
        class_hash: &ClassHash,
    ) -> StateResult<ContractClass> {
        let contract_class = self.class_hash_to_class.get(class_hash).cloned();
        match contract_class {
            Some(contract_class) => Ok(contract_class),
            _ => Err(StateError::UndeclaredClassHash(*class_hash)),
        }
    }

    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        let class_hash =
            self.address_to_class_hash.get(&contract_address).copied().unwrap_or_default();
        Ok(class_hash)
    }

    fn get_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
    ) -> StateResult<starknet_api::core::CompiledClassHash> {
        let compiled_class_hash =
            self.class_hash_to_compiled_class_hash.get(&class_hash).copied().unwrap_or_default();
        Ok(compiled_class_hash)
    }
}

>>>>>>> origin/main-v0.13.0
#[derive(Default)]
pub struct NonceManager {
    next_nonce: HashMap<ContractAddress, Felt252>,
}

impl NonceManager {
    pub fn next(&mut self, account_address: ContractAddress) -> Nonce {
        let zero = Felt252::zero();
        let next_felt252 = self.next_nonce.get(&account_address).unwrap_or(&zero);
        let next = Nonce(felt_to_stark_felt(next_felt252));
        self.next_nonce.insert(account_address, Felt252::one() + next_felt252);
        next
    }

    /// Decrements the nonce of the account, unless it is zero.
    pub fn rollback(&mut self, account_address: ContractAddress) {
        let zero = Felt252::zero();
        let current = self.next_nonce.get(&account_address).unwrap_or(&zero);
        if !current.is_zero() {
            self.next_nonce.insert(account_address, current - 1);
        }
    }
}

#[derive(Default)]
pub struct SaltManager {
    next_salt: u8,
}

impl SaltManager {
    pub fn next_salt(&mut self) -> ContractAddressSalt {
        let next_contract_address_salt = ContractAddressSalt(stark_felt!(self.next_salt));
        self.next_salt += 1;
        next_contract_address_salt
    }
}

pub fn pad_address_to_64(address: &str) -> String {
    let trimmed_address = address.strip_prefix("0x").unwrap_or(address);
    String::from("0x") + format!("{trimmed_address:0>64}").as_str()
}

pub fn get_raw_contract_class(contract_path: &str) -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), contract_path].iter().collect();
    fs::read_to_string(path).unwrap()
}

pub fn get_deprecated_contract_class(contract_path: &str) -> DeprecatedContractClass {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), contract_path].iter().collect();
    let contract = fs::read_to_string(path).unwrap();
    let mut raw_contract_class: serde_json::Value = serde_json::from_str(&contract).unwrap();

    // ABI is not required for execution.
    raw_contract_class
        .as_object_mut()
        .expect("A compiled contract must be a JSON object.")
        .remove("abi");

    serde_json::from_value(raw_contract_class).unwrap()
}

pub fn get_test_contract_class() -> ContractClass {
    ContractClassV0::from_file(TEST_CONTRACT_CAIRO0_PATH).into()
}

pub fn trivial_external_entry_point() -> CallEntryPoint {
    let contract_address = contract_address!(TEST_CONTRACT_ADDRESS);
    CallEntryPoint {
        class_hash: None,
        code_address: Some(contract_address),
        entry_point_type: EntryPointType::External,
        entry_point_selector: EntryPointSelector(stark_felt!(0_u8)),
        calldata: calldata![],
        storage_address: contract_address,
        caller_address: ContractAddress::default(),
        call_type: CallType::Call,
        initial_gas: constants::INITIAL_GAS_COST,
    }
}

<<<<<<< HEAD
fn default_testing_resource_bounds() -> ResourceBoundsMapping {
    ResourceBoundsMapping::try_from(vec![
        (Resource::L1Gas, ResourceBounds { max_amount: 0, max_price_per_unit: 1 }),
        // TODO(Dori, 1/2/2024): When fee market is developed, change the default price of
        //   L2 gas.
        (Resource::L2Gas, ResourceBounds { max_amount: 0, max_price_per_unit: 0 }),
||||||| e3ccd803
pub fn trivial_external_entry_point_security_test() -> CallEntryPoint {
    CallEntryPoint {
        storage_address: contract_address!(SECURITY_TEST_CONTRACT_ADDRESS),
        ..trivial_external_entry_point()
    }
}

fn common_map_setup() -> HashMap<ContractAddress, ClassHash> {
    HashMap::from([
        (contract_address!(TEST_CONTRACT_ADDRESS), class_hash!(TEST_CLASS_HASH)),
        (contract_address!(TEST_CONTRACT_ADDRESS_2), class_hash!(TEST_CLASS_HASH)),
        (
            contract_address!(TEST_PAIR_SKELETON_CONTRACT_ADDRESS1),
            class_hash!(TEST_PAIR_SKELETON_CONTRACT_CLASS_HASH),
        ),
    ])
}

fn get_class_hash_to_v0_class_mapping() -> ContractClassMapping {
    HashMap::from([
        (
            class_hash!(TEST_CLASS_HASH),
            ContractClassV0::from_file(TEST_CONTRACT_CAIRO0_PATH).into(),
        ),
        (
            class_hash!(SECURITY_TEST_CLASS_HASH),
            ContractClassV0::from_file(SECURITY_TEST_CONTRACT_CAIRO0_PATH).into(),
        ),
        (
            class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
            ContractClassV0::from_file(TEST_EMPTY_CONTRACT_CAIRO0_PATH).into(),
        ),
        (
            class_hash!(TEST_PAIR_SKELETON_CONTRACT_CLASS_HASH),
            ContractClassV0::from_file(TEST_PAIR_SKELETON_CONTRACT_PATH).into(),
        ),
    ])
}

fn get_class_hash_to_v1_class_mapping() -> ContractClassMapping {
    HashMap::from([
        (
            class_hash!(TEST_CLASS_HASH),
            ContractClassV1::from_file(TEST_CONTRACT_CAIRO1_PATH).into(),
        ),
        (
            class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
            ContractClassV1::from_file(TEST_EMPTY_CONTRACT_CAIRO1_PATH).into(),
        ),
        (
            class_hash!(LEGACY_TEST_CLASS_HASH),
            ContractClassV1::from_file(LEGACY_TEST_CONTRACT_CAIRO1_PATH).into(),
        ),
    ])
}

fn get_address_to_v0_class_hash() -> HashMap<ContractAddress, ClassHash> {
    let mut address_to_class_hash = common_map_setup();
    address_to_class_hash.insert(
        contract_address!(SECURITY_TEST_CONTRACT_ADDRESS),
        class_hash!(SECURITY_TEST_CLASS_HASH),
    );
    address_to_class_hash
}

fn get_storage_values_for_deprecated_test_state()
-> HashMap<(ContractAddress, StorageKey), StarkFelt> {
    let pair_address = contract_address!(TEST_PAIR_SKELETON_CONTRACT_ADDRESS1);
    let reserve0_address = get_storage_var_address("_reserve0", &[]);
    let reserve1_address = get_storage_var_address("_reserve1", &[]);
    // Override the pair's reserves data, since the constructor is not called.
    HashMap::from([
        ((pair_address, reserve0_address), stark_felt!(RESERVE_0)),
        ((pair_address, reserve1_address), stark_felt!(RESERVE_1)),
=======
pub fn trivial_external_entry_point_security_test() -> CallEntryPoint {
    CallEntryPoint {
        storage_address: contract_address!(SECURITY_TEST_CONTRACT_ADDRESS),
        ..trivial_external_entry_point()
    }
}

fn common_map_setup() -> HashMap<ContractAddress, ClassHash> {
    HashMap::from([
        (contract_address!(TEST_CONTRACT_ADDRESS), class_hash!(TEST_CLASS_HASH)),
        (contract_address!(TEST_CONTRACT_ADDRESS_2), class_hash!(TEST_CLASS_HASH)),
        (
            contract_address!(TEST_PAIR_SKELETON_CONTRACT_ADDRESS1),
            class_hash!(TEST_PAIR_SKELETON_CONTRACT_CLASS_HASH),
        ),
    ])
}

fn get_class_hash_to_v0_class_mapping() -> ContractClassMapping {
    HashMap::from([
        (
            class_hash!(TEST_CLASS_HASH),
            ContractClassV0::from_file(TEST_CONTRACT_CAIRO0_PATH).into(),
        ),
        (
            class_hash!(SECURITY_TEST_CLASS_HASH),
            ContractClassV0::from_file(SECURITY_TEST_CONTRACT_CAIRO0_PATH).into(),
        ),
        (
            class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
            ContractClassV0::from_file(TEST_EMPTY_CONTRACT_CAIRO0_PATH).into(),
        ),
        (
            class_hash!(TEST_PAIR_SKELETON_CONTRACT_CLASS_HASH),
            ContractClassV0::from_file(TEST_PAIR_SKELETON_CONTRACT_PATH).into(),
        ),
    ])
}

fn get_class_hash_to_v1_class_mapping() -> ContractClassMapping {
    HashMap::from([
        (
            class_hash!(TEST_CLASS_HASH),
            ContractClassV1::from_file(TEST_CONTRACT_CAIRO1_PATH).into(),
        ),
        (
            class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
            ContractClassV1::from_file(TEST_EMPTY_CONTRACT_CAIRO1_PATH).into(),
        ),
        (
            class_hash!(LEGACY_TEST_CLASS_HASH),
            ContractClassV1::from_file(LEGACY_TEST_CONTRACT_CAIRO1_PATH).into(),
        ),
    ])
}

fn get_address_to_v0_class_hash() -> HashMap<ContractAddress, ClassHash> {
    let mut address_to_class_hash = common_map_setup();
    address_to_class_hash.insert(
        contract_address!(SECURITY_TEST_CONTRACT_ADDRESS),
        class_hash!(SECURITY_TEST_CLASS_HASH),
    );
    address_to_class_hash
}

fn get_storage_values_for_deprecated_test_state() -> HashMap<StorageEntry, StarkFelt> {
    let pair_address = contract_address!(TEST_PAIR_SKELETON_CONTRACT_ADDRESS1);
    let reserve0_address = get_storage_var_address("_reserve0", &[]);
    let reserve1_address = get_storage_var_address("_reserve1", &[]);
    // Override the pair's reserves data, since the constructor is not called.
    HashMap::from([
        ((pair_address, reserve0_address), stark_felt!(RESERVE_0)),
        ((pair_address, reserve1_address), stark_felt!(RESERVE_1)),
>>>>>>> origin/main-v0.13.0
    ])
    .unwrap()
}

// Transactions.

#[macro_export]
macro_rules! check_inner_exc_for_custom_hint {
    ($inner_exc:expr, $expected_hint:expr) => {
        if let cairo_vm::vm::errors::vm_errors::VirtualMachineError::Hint(hint) = $inner_exc {
            if let cairo_vm::vm::errors::hint_errors::HintError::CustomHint(custom_hint) = &hint.1 {
                assert_eq!(custom_hint.as_ref(), $expected_hint)
            } else {
                panic!("Unexpected hint: {:?}", hint);
            }
        } else {
            panic!("Unexpected structure for inner_exc: {:?}", $inner_exc);
        }
    };
}

#[macro_export]
macro_rules! check_inner_exc_for_invalid_scenario {
    ($inner_exc:expr) => {
        if let cairo_vm::vm::errors::vm_errors::VirtualMachineError::DiffAssertValues(_) =
            $inner_exc
        {
        } else {
            panic!("Unexpected structure for inner_exc: {:?}", $inner_exc)
        }
    };
}

#[macro_export]
macro_rules! check_entry_point_execution_error {
    ($error:expr, $expected_hint:expr $(,)?) => {
        if let EntryPointExecutionError::VirtualMachineExecutionErrorWithTrace {
            source:
                VirtualMachineExecutionError::CairoRunError(
                    cairo_vm::vm::errors::cairo_run_errors::CairoRunError::VmException(
                        cairo_vm::vm::errors::vm_exception::VmException { inner_exc, .. },
                    ),
                ),
            ..
        } = $error
        {
            match $expected_hint {
                Some(expected_hint) => {
                    $crate::check_inner_exc_for_custom_hint!(inner_exc, expected_hint)
                }
                None => $crate::check_inner_exc_for_invalid_scenario!(inner_exc),
            };
        } else {
            panic!("Unexpected structure for error: {:?}", $error);
        }
    };
}

/// Checks that the given error is a `HintError::CustomHint` with the given hint.
#[macro_export]
macro_rules! check_entry_point_execution_error_for_custom_hint {
    ($error:expr, $expected_hint:expr $(,)?) => {
        $crate::check_entry_point_execution_error!($error, Some($expected_hint))
    };
}

#[macro_export]
macro_rules! check_transaction_execution_error_inner {
    ($error:expr, $expected_hint:expr, $variant:ident $(,)?) => {
        match $error {
            TransactionExecutionError::$variant(error) => {
                $crate::check_entry_point_execution_error!(error, $expected_hint)
            }
            _ => panic!("Unexpected structure for error: {:?}", $error),
        }
    };
}

#[macro_export]
macro_rules! check_transaction_execution_error_for_custom_hint {
    ($error:expr, $expected_hint:expr, $validate_constructor:expr $(,)?) => {
        if $validate_constructor {
            $crate::check_transaction_execution_error_inner!(
                $error,
                Some($expected_hint),
                ContractConstructorExecutionFailed,
            );
        } else {
            $crate::check_transaction_execution_error_inner!(
                $error,
                Some($expected_hint),
                ValidateTransactionError,
            );
        }
    };
}

/// Checks that a given error is an assertion error with the expected message.
/// Formatted for test_validate_accounts_tx.
#[macro_export]
macro_rules! check_transaction_execution_error_for_invalid_scenario {
    ($cairo_version:expr, $error:expr, $validate_constructor:expr $(,)?) => {
        match $cairo_version {
            CairoVersion::Cairo0 => {
                if $validate_constructor {
                    $crate::check_transaction_execution_error_inner!(
                        $error,
                        None::<&str>,
                        ContractConstructorExecutionFailed,
                    );
                } else {
                    $crate::check_transaction_execution_error_inner!(
                        $error,
                        None::<&str>,
                        ValidateTransactionError,
                    );
                }
            }
            CairoVersion::Cairo1 => {
                if let TransactionExecutionError::ValidateTransactionError(error) = $error {
                    assert_eq!(
                        error.to_string(),
                        "Execution failed. Failure reason: 0x496e76616c6964207363656e6172696f \
                         ('Invalid scenario')."
                    )
                }
            }
        }
    };
}

pub fn create_calldata(
    contract_address: ContractAddress,
    entry_point_name: &str,
    entry_point_args: &[StarkFelt],
) -> Calldata {
    let n_args = u128::try_from(entry_point_args.len()).expect("Calldata too big");
    let n_args = StarkFelt::from(n_args);

    let mut calldata = vec![
        *contract_address.0.key(),              // Contract address.
        selector_from_name(entry_point_name).0, // EP selector name.
        n_args,
    ];
    calldata.extend(entry_point_args);

    Calldata(calldata.into())
}
