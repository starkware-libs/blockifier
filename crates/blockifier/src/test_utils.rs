pub mod cached_state;
pub mod contracts;
pub mod declare;
pub mod deploy_account;
pub mod dict_state_reader;
pub mod invoke;
pub mod struct_impls;

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use cairo_felt::Felt252;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::errors::vm_exception::VmException;
use num_traits::{One, Zero};
use starknet_api::core::{ContractAddress, EntryPointSelector, Nonce, PatriciaKey};
use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass, EntryPointType,
};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Calldata, Resource, ResourceBounds, ResourceBoundsMapping};
use starknet_api::{calldata, contract_address, patricia_key, stark_felt};
use strum_macros::EnumIter;

use crate::abi::abi_utils::{get_fee_token_var_address, selector_from_name};
use crate::abi::constants::{self};
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{CallEntryPoint, CallType};
use crate::execution::errors::{EntryPointExecutionError, VirtualMachineExecutionError};
use crate::execution::execution_utils::felt_to_stark_felt;
use crate::test_utils::contracts::{FeatureContract, FeatureContractId};
use crate::utils::const_max;

// Addresses.
pub const TEST_SEQUENCER_ADDRESS: &str = "0x1000";
pub const TEST_ERC20_CONTRACT_ADDRESS: &str = "0x1001";
pub const TEST_ERC20_CONTRACT_ADDRESS2: &str = "0x1002";
pub const TEST_PAIR_SKELETON_CONTRACT_ADDRESS1: &str = "0x1003";

// Class hashes.
// TODO(Adi, 15/01/2023): Remove and compute the class hash corresponding to the ERC20 contract in
// starkgate once we use the real ERC20 contract.
pub const TEST_ERC20_CONTRACT_CLASS_HASH: &str = "0x1010";
pub const TEST_PAIR_SKELETON_CONTRACT_CLASS_HASH: &str = "0x1011";

// Paths.
pub const ERC20_CONTRACT_PATH: &str =
    "./ERC20_without_some_syscalls/ERC20/erc20_contract_without_some_syscalls_compiled.json";
pub const TEST_PAIR_SKELETON_CONTRACT_PATH: &str =
    "./feature_contracts/cairo0/compiled/test_pair_skeleton_compiled.json";

#[derive(Copy, Clone, EnumIter, PartialEq)]
pub enum CairoVersion {
    Cairo0,
    Cairo1,
}

// Storage keys.
pub fn test_erc20_sequencer_balance_key() -> StorageKey {
    get_fee_token_var_address(&contract_address!(TEST_SEQUENCER_ADDRESS))
}
pub fn test_erc20_account_balance_key(cairo_version: CairoVersion) -> StorageKey {
    let account =
        FeatureContract::new(FeatureContractId::AccountWithoutValidations, cairo_version, 0);
    get_fee_token_var_address(&account.address)
}
pub fn test_erc20_faulty_account_balance_key() -> StorageKey {
    let faulty_account =
        FeatureContract::new(FeatureContractId::FaultyAccount, CairoVersion::Cairo0, 0);
    get_fee_token_var_address(&faulty_account.address)
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

// The reserves values in the mocked STRK-ETH pair contract.
pub const RESERVE_0: u32 = 100000;
pub const RESERVE_1: u32 = 100;

// The block timestamp of the BlockContext being used for testing.
pub const CURRENT_BLOCK_TIMESTAMP: u64 = 1072023;

pub const CHAIN_ID_NAME: &str = "SN_GOERLI";

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

pub fn pad_address_to_64(address: ContractAddress) -> String {
    let hex = format!("{}", address.0.key());
    let trimmed_address = hex.strip_prefix("0x").unwrap_or(hex.as_str());
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
    FeatureContract::new(FeatureContractId::TestContract, CairoVersion::Cairo0, 0).get_class()
}

pub fn trivial_external_entry_point(cairo_version: CairoVersion) -> CallEntryPoint {
    let contract_address = FeatureContractId::TestContract.get_address(cairo_version, 0);
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

pub fn trivial_external_entry_point_security_test(cairo_version: CairoVersion) -> CallEntryPoint {
    CallEntryPoint {
        storage_address: FeatureContract::new(
            FeatureContractId::SecurityTests,
            CairoVersion::Cairo0,
            0,
        )
        .address,
        ..trivial_external_entry_point(cairo_version)
    }
}

fn default_testing_resource_bounds() -> ResourceBoundsMapping {
    ResourceBoundsMapping::try_from(vec![
        (Resource::L1Gas, ResourceBounds { max_amount: 0, max_price_per_unit: 1 }),
        // TODO(Dori, 1/2/2024): When fee market is developed, change the default price of
        //   L2 gas.
        (Resource::L2Gas, ResourceBounds { max_amount: 0, max_price_per_unit: 0 }),
    ])
    .unwrap()
}

// Transactions.

/// Checks that the given error is a `HintError::CustomHint` with the given hint.
pub fn check_entry_point_execution_error_for_custom_hint(
    error: &EntryPointExecutionError,
    expected_hint: &str,
) {
    if let EntryPointExecutionError::VirtualMachineExecutionErrorWithTrace {
        source:
            VirtualMachineExecutionError::CairoRunError(CairoRunError::VmException(VmException {
                inner_exc: VirtualMachineError::Hint(hint),
                ..
            })),
        ..
    } = error
    {
        if let HintError::CustomHint(custom_hint) = &hint.1 {
            assert_eq!(custom_hint.as_ref(), expected_hint)
        } else {
            panic!("Unexpected hint: {:?}", hint);
        }
    } else {
        panic!("Unexpected structure for error: {:?}", error);
    }
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
