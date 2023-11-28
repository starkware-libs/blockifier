pub mod cached_state;
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
use starknet_api::core::{
    calculate_contract_address, ClassHash, ContractAddress, EntryPointSelector, Nonce, PatriciaKey,
};
use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass, EntryPointType,
};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransactionV0V1, DeployAccountTransactionV1, Fee,
    TransactionHash, TransactionSignature,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};

use crate::abi::abi_utils::{get_fee_token_var_address, selector_from_name};
use crate::abi::constants::{self};
use crate::execution::contract_class::{ContractClass, ContractClassV0};
use crate::execution::entry_point::{CallEntryPoint, CallType};
use crate::execution::errors::{EntryPointExecutionError, VirtualMachineExecutionError};
use crate::execution::execution_utils::felt_to_stark_felt;
use crate::transaction::transactions::DeployAccountTransaction;
use crate::utils::const_max;

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
pub const TEST_PAIR_SKELETON_CONTRACT_ADDRESS1: &str = "0x1003";

// Class hashes.
pub const TEST_CLASS_HASH: &str = "0x110";
pub const TEST_ACCOUNT_CONTRACT_CLASS_HASH: &str = "0x111";
pub const TEST_EMPTY_CONTRACT_CLASS_HASH: &str = "0x112";
pub const TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH: &str = "0x113";
pub const SECURITY_TEST_CLASS_HASH: &str = "0x114";
pub const TEST_GRINDY_ACCOUNT_CONTRACT_CLASS_HASH: &str = "0x115";
pub const LEGACY_TEST_CLASS_HASH: &str = "0x116";
// TODO(Adi, 15/01/2023): Remove and compute the class hash corresponding to the ERC20 contract in
// starkgate once we use the real ERC20 contract.
pub const TEST_ERC20_CONTRACT_CLASS_HASH: &str = "0x1010";
pub const TEST_PAIR_SKELETON_CONTRACT_CLASS_HASH: &str = "0x1011";

// Paths.
pub const ACCOUNT_CONTRACT_CAIRO1_PATH: &str =
    "./feature_contracts/cairo1/compiled/account_contract.casm.json";
pub const ACCOUNT_CONTRACT_CAIRO0_PATH: &str =
    "./feature_contracts/cairo0/compiled/account_without_validations_compiled.json";
pub const GRINDY_ACCOUNT_CONTRACT_CAIRO0_PATH: &str =
    "./feature_contracts/cairo0/compiled/account_with_long_validate_compiled.json";
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
pub const TEST_PAIR_SKELETON_CONTRACT_PATH: &str =
    "./feature_contracts/cairo0/compiled/test_pair_skeleton_compiled.json";

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

pub fn trivial_external_entry_point_security_test() -> CallEntryPoint {
    CallEntryPoint {
        storage_address: contract_address!(SECURITY_TEST_CONTRACT_ADDRESS),
        ..trivial_external_entry_point()
    }
}

// Transactions.

pub fn deploy_account_tx(
    class_hash: &str,
    max_fee: Fee,
    constructor_calldata: Option<Calldata>,
    signature: Option<TransactionSignature>,
    nonce_manager: &mut NonceManager,
) -> DeployAccountTransaction {
    deploy_account_tx_with_salt(
        class_hash,
        max_fee,
        constructor_calldata,
        ContractAddressSalt::default(),
        signature,
        nonce_manager,
    )
}

pub fn deploy_account_tx_with_salt(
    class_hash: &str,
    max_fee: Fee,
    constructor_calldata: Option<Calldata>,
    contract_address_salt: ContractAddressSalt,
    signature: Option<TransactionSignature>,
    nonce_manager: &mut NonceManager,
) -> DeployAccountTransaction {
    let class_hash = class_hash!(class_hash);
    let deployer_address = ContractAddress::default();
    let constructor_calldata = constructor_calldata.unwrap_or_default();
    let contract_address = calculate_contract_address(
        contract_address_salt,
        class_hash,
        &constructor_calldata,
        deployer_address,
    )
    .unwrap();

    let tx = starknet_api::transaction::DeployAccountTransaction::V1(DeployAccountTransactionV1 {
        max_fee,
        signature: signature.unwrap_or_default(),
        class_hash,
        contract_address_salt,
        constructor_calldata,
        nonce: nonce_manager.next(contract_address),
    });

    DeployAccountTransaction::new(tx, TransactionHash::default(), contract_address)
}

pub fn declare_tx(
    class_hash: &str,
    sender_address: ContractAddress,
    max_fee: Fee,
    signature: Option<TransactionSignature>,
) -> DeclareTransactionV0V1 {
    DeclareTransactionV0V1 {
        max_fee,
        class_hash: class_hash!(class_hash),
        sender_address,
        signature: signature.unwrap_or_default(),
        ..Default::default()
    }
}

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
