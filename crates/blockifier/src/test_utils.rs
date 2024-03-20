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
use std::sync::Arc;

use cairo_felt::Felt252;
use cairo_native::starknet::SyscallResult;
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
    Calldata, ContractAddressSalt, Resource, ResourceBounds, ResourceBoundsMapping,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};
use starknet_types_core::felt::Felt;

use crate::abi::abi_utils::{get_fee_token_var_address, selector_from_name};
use crate::context::{BlockContext, TransactionContext};
use crate::execution::call_info::{CallInfo, OrderedEvent};
use crate::execution::common_hints::ExecutionMode;
use crate::execution::contract_class::{ContractClass, ContractClassV0};
use crate::execution::entry_point::{
    CallEntryPoint, CallType, ConstructorContext, EntryPointExecutionContext,
};
use crate::execution::execution_utils::{execute_deployment, felt_to_stark_felt}; /* TODO rename to felt252_to_stark_felt */
use crate::execution::sierra_utils::{
    contract_address_to_felt, felt_to_starkfelt, starkfelt_to_felt,
};
use crate::execution::syscalls::hint_processor::{
    FAILED_TO_CALCULATE_CONTRACT_ADDRESS, FAILED_TO_EXECUTE_CALL,
};
use crate::state::cached_state::CachedState;
use crate::state::state_api::State;
use crate::test_utils::cached_state::get_erc20_class_hash_mapping;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::transaction::objects::TransactionInfo;
use crate::utils::const_max;
use crate::versioned_constants::VersionedConstants;

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
pub const TEST_ERC20_FULL_CONTRACT_ADDRESS: &str = "0x1003";

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

pub const TEST_ERC20_FULL_CONTRACT_CLASS_HASH: &str = "0x1011";

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
pub const TEST_CONTRACT_SIERRA_PATH: &str =
    "./feature_contracts/cairo1/compiled/sierra_test_contract.sierra.json";
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
pub const ERC20_FULL_CONTRACT_PATH: &str =
    "./oz_erc20/target/dev/oz_erc20_OZ_ERC20.contract_class.json";

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
    get_fee_token_var_address(contract_address!(TEST_SEQUENCER_ADDRESS))
}
pub fn test_erc20_account_balance_key() -> StorageKey {
    get_fee_token_var_address(contract_address!(TEST_ACCOUNT_CONTRACT_ADDRESS))
}
pub fn test_erc20_faulty_account_balance_key() -> StorageKey {
    get_fee_token_var_address(contract_address!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS))
}

// The max_fee / resource bounds used for txs in this test.
pub const MAX_L1_GAS_AMOUNT: u64 = 1000000;
#[allow(clippy::as_conversions)]
pub const MAX_L1_GAS_AMOUNT_U128: u128 = MAX_L1_GAS_AMOUNT as u128;
pub const MAX_L1_GAS_PRICE: u128 = DEFAULT_STRK_L1_GAS_PRICE;
pub const MAX_RESOURCE_COMMITMENT: u128 = MAX_L1_GAS_AMOUNT_U128 * MAX_L1_GAS_PRICE;
pub const MAX_FEE: u128 = MAX_L1_GAS_AMOUNT_U128 * DEFAULT_ETH_L1_GAS_PRICE;

// The amount of test-token allocated to the account in this test, set to a multiple of the max
// amount deprecated / non-deprecated transactions commit to paying.
pub const BALANCE: u128 = 10 * const_max(MAX_FEE, MAX_RESOURCE_COMMITMENT);

pub const DEFAULT_ETH_L1_GAS_PRICE: u128 = 100 * u128::pow(10, 9); // Given in units of Wei.
pub const DEFAULT_STRK_L1_GAS_PRICE: u128 = 100 * u128::pow(10, 9); // Given in units of STRK.
pub const DEFAULT_ETH_L1_DATA_GAS_PRICE: u128 = u128::pow(10, 6); // Given in units of Wei.
pub const DEFAULT_STRK_L1_DATA_GAS_PRICE: u128 = u128::pow(10, 9); // Given in units of STRK.

// The block number of the BlockContext being used for testing.
pub const CURRENT_BLOCK_NUMBER: u64 = 2001;
pub const CURRENT_BLOCK_NUMBER_FOR_VALIDATE: u64 = 2000;

// The block timestamp of the BlockContext being used for testing.
pub const CURRENT_BLOCK_TIMESTAMP: u64 = 1072023;
pub const CURRENT_BLOCK_TIMESTAMP_FOR_VALIDATE: u64 = 1069200;

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
    fs::read_to_string(path.clone()).expect(&format!("File expected at {}", path.display()))
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
    trivial_external_entry_point_with_address(contract_address!(TEST_CONTRACT_ADDRESS))
}

pub fn trivial_external_entry_point_new(contract: FeatureContract) -> CallEntryPoint {
    let address = contract.get_instance_address(0);
    trivial_external_entry_point_with_address(address)
}

pub fn trivial_external_entry_point_with_address(
    contract_address: ContractAddress,
) -> CallEntryPoint {
    CallEntryPoint {
        class_hash: None,
        code_address: Some(contract_address),
        entry_point_type: EntryPointType::External,
        entry_point_selector: EntryPointSelector(stark_felt!(0_u8)),
        calldata: calldata![],
        storage_address: contract_address,
        caller_address: ContractAddress::default(),
        call_type: CallType::Call,
        initial_gas: VersionedConstants::create_for_testing().gas_cost("initial_gas_cost"),
    }
}

pub fn erc20_external_entry_point() -> CallEntryPoint {
    trivial_external_entry_point_with_address(contract_address!(TEST_ERC20_FULL_CONTRACT_ADDRESS))
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

#[macro_export]
macro_rules! check_inner_exc_for_custom_hint {
    ($inner_exc:expr, $expected_hint:expr) => {
        if let cairo_vm::vm::errors::vm_errors::VirtualMachineError::Hint(hint) = $inner_exc {
            if let cairo_vm::vm::errors::hint_errors::HintError::Internal(
                cairo_vm::vm::errors::vm_errors::VirtualMachineError::Other(error),
            ) = &hint.1
            {
                assert_eq!(error.to_string(), $expected_hint.to_string());
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
                cairo_vm::vm::errors::cairo_run_errors::CairoRunError::VmException(
                    cairo_vm::vm::errors::vm_exception::VmException { inner_exc, .. },
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

/// Calldata for a trivial entry point in the test contract.
pub fn create_trivial_calldata(test_contract_address: ContractAddress) -> Calldata {
    create_calldata(
        test_contract_address,
        "return_result",
        &[stark_felt!(2_u8)], // Calldata: num.
    )
}

pub fn create_erc20_deploy_test_state() -> CachedState<DictStateReader> {
    let address_to_class_hash: HashMap<ContractAddress, ClassHash> = HashMap::from([(
        contract_address!(TEST_ERC20_FULL_CONTRACT_ADDRESS),
        class_hash!(TEST_ERC20_FULL_CONTRACT_CLASS_HASH),
    )]);

    CachedState::from(DictStateReader {
        address_to_class_hash,
        class_hash_to_class: get_erc20_class_hash_mapping(),
        ..Default::default()
    })
}

pub fn deploy_contract(
    state: &mut dyn State,
    class_hash: Felt,
    contract_address_salt: Felt,
    calldata: &[Felt],
) -> SyscallResult<(Felt, Vec<Felt>)> {
    let deployer_address = ContractAddress::default();

    let class_hash = ClassHash(felt_to_starkfelt(class_hash));

    let wrapper_calldata =
        Calldata(Arc::new(calldata.iter().map(|felt| felt_to_starkfelt(*felt)).collect()));

    let calculated_contract_address = calculate_contract_address(
        ContractAddressSalt(felt_to_starkfelt(contract_address_salt)),
        class_hash,
        &wrapper_calldata,
        deployer_address,
    )
    .map_err(|_| vec![Felt::from_hex(FAILED_TO_CALCULATE_CONTRACT_ADDRESS).unwrap()])?;

    let ctor_context = ConstructorContext {
        class_hash,
        code_address: Some(calculated_contract_address),
        storage_address: calculated_contract_address,
        caller_address: deployer_address,
    };

    let call_info = execute_deployment(
        state,
        &mut Default::default(),
        &mut EntryPointExecutionContext::new(
            Arc::new(TransactionContext {
                block_context: BlockContext::create_for_testing(),
                tx_info: TransactionInfo::Current(Default::default()),
            }),
            ExecutionMode::Execute,
            false,
        )
        .unwrap(),
        ctor_context,
        wrapper_calldata,
        u64::MAX,
    )
    .map_err(|_| vec![Felt::from_hex(FAILED_TO_EXECUTE_CALL).unwrap()])?;

    let return_data = call_info.execution.retdata.0.into_iter().map(starkfelt_to_felt).collect();
    let contract_address_felt = starkfelt_to_felt(*calculated_contract_address.0.key());
    Ok((contract_address_felt, return_data))
}

pub fn prepare_erc20_deploy_test_state() -> (ContractAddress, CachedState<DictStateReader>) {
    let mut state = create_erc20_deploy_test_state();

    let class_hash = Felt::from_hex(TEST_ERC20_FULL_CONTRACT_CLASS_HASH).unwrap();

    let (contract_address, _) = deploy_contract(
        &mut state,
        class_hash,
        Felt::from(0),
        &[
            contract_address_to_felt(Signers::Alice.into()), // Recipient
            contract_address_to_felt(Signers::Alice.into()), // Owner
        ],
    )
    .unwrap();

    let contract_address =
        ContractAddress(PatriciaKey::try_from(felt_to_starkfelt(contract_address)).unwrap());

    (contract_address, state)
}

#[derive(Debug, Clone, Copy)]
pub enum Signers {
    Alice,
    Bob,
    Charlie,
}

impl Signers {
    pub fn get_address(&self) -> ContractAddress {
        match self {
            Signers::Alice => ContractAddress(patricia_key!(0x001u128)),
            Signers::Bob => ContractAddress(patricia_key!(0x002u128)),
            Signers::Charlie => ContractAddress(patricia_key!(0x003u128)),
        }
    }
}

impl Into<ContractAddress> for Signers {
    fn into(self) -> ContractAddress {
        self.get_address()
    }
}

impl Into<Felt> for Signers {
    fn into(self) -> Felt {
        contract_address_to_felt(self.get_address())
    }
}

impl Into<StarkFelt> for Signers {
    fn into(self) -> StarkFelt {
        felt_to_starkfelt(contract_address_to_felt(self.get_address()))
    }
}

#[derive(Debug, Clone)]
pub struct TestEvent {
    pub data: Vec<Felt>,
    pub keys: Vec<Felt>,
}

impl From<OrderedEvent> for TestEvent {
    fn from(value: OrderedEvent) -> Self {
        let event_data = value.event.data.0.iter().map(|e| starkfelt_to_felt(*e)).collect();
        let event_keys = value.event.keys.iter().map(|e| starkfelt_to_felt(e.0)).collect();
        Self { data: event_data, keys: event_keys }
    }
}

pub struct TestContext {
    pub contract_address: ContractAddress,
    pub state: CachedState<DictStateReader>,
    pub caller_address: ContractAddress,
    pub events: Vec<TestEvent>,
}

impl TestContext {
    pub fn new() -> Self {
        let (contract_address, state) = prepare_erc20_deploy_test_state();
        Self { contract_address, state, caller_address: contract_address, events: vec![] }
    }

    pub fn with_caller(mut self, caller_address: ContractAddress) -> Self {
        self.caller_address = caller_address;
        self
    }

    pub fn call_entry_point(
        &mut self,
        entry_point_name: &str,
        calldata: Vec<StarkFelt>,
    ) -> Vec<Felt> {
        let result = self.call_entry_point_raw(entry_point_name, calldata);
        result.execution.retdata.0.iter().map(|felt| starkfelt_to_felt(*felt)).collect()
    }

    pub fn call_entry_point_raw(
        &mut self,
        entry_point_name: &str,
        calldata: Vec<StarkFelt>,
    ) -> CallInfo {
        let entry_point_selector = selector_from_name(entry_point_name);
        let calldata = Calldata(Arc::new(calldata));

        let entry_point_call = CallEntryPoint {
            calldata,
            entry_point_selector,
            code_address: Some(self.contract_address),
            storage_address: self.contract_address,
            caller_address: self.caller_address,
            ..erc20_external_entry_point()
        };

        let result = entry_point_call.execute_directly(&mut self.state).unwrap();

        let events = result.execution.events.clone();

        self.events.extend(events.iter().map(|e| e.clone().into()));

        result
    }

    pub fn get_event(&self, index: usize) -> Option<TestEvent> {
        self.events.get(index).cloned()
    }

    pub fn get_caller(&self) -> ContractAddress {
        self.caller_address
    }
}
