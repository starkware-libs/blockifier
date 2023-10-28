use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use cairo_felt::Felt252;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::errors::vm_exception::VmException;
use cairo_vm::vm::runners::builtin_runner::{
    BITWISE_BUILTIN_NAME, EC_OP_BUILTIN_NAME, HASH_BUILTIN_NAME, OUTPUT_BUILTIN_NAME,
    POSEIDON_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME, SIGNATURE_BUILTIN_NAME,
};
use num_traits::{One, Zero};
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{
    calculate_contract_address, ChainId, ClassHash, CompiledClassHash, ContractAddress,
    EntryPointSelector, Nonce, PatriciaKey,
};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass, EntryPointType,
};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    AccountDeploymentData, Calldata, ContractAddressSalt, DeclareTransactionV0V1,
    DeployAccountTransactionV1, Fee, InvokeTransactionV0, InvokeTransactionV1, InvokeTransactionV3,
    PaymasterData, Resource, ResourceBounds, ResourceBoundsMapping, Tip, TransactionHash,
    TransactionSignature, TransactionVersion,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};

use crate::abi::abi_utils::{
    get_fee_token_var_address, get_storage_var_address, selector_from_name,
};
use crate::abi::constants::{self, MAX_STEPS_PER_TX, MAX_VALIDATE_STEPS_PER_TX};
use crate::block_context::{BlockContext, FeeTokenAddresses, GasPrices};
use crate::execution::call_info::{CallExecution, CallInfo, Retdata};
use crate::execution::contract_class::{ContractClass, ContractClassV0, ContractClassV1};
use crate::execution::entry_point::{
    CallEntryPoint, CallType, EntryPointExecutionContext, EntryPointExecutionResult,
    ExecutionResources,
};
use crate::execution::errors::{EntryPointExecutionError, VirtualMachineExecutionError};
use crate::execution::execution_utils::felt_to_stark_felt;
use crate::state::cached_state::{CachedState, ContractClassMapping, ContractStorageKey};
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader, StateResult};
use crate::transaction::constants::EXECUTE_ENTRY_POINT_NAME;
use crate::transaction::objects::{AccountTransactionContext, DeprecatedAccountTransactionContext};
use crate::transaction::transactions::{DeployAccountTransaction, InvokeTransaction};
use crate::utils::const_max;

// Addresses.
pub const TEST_CONTRACT_ADDRESS: &str = "0x100";
pub const TEST_CONTRACT_ADDRESS_2: &str = "0x200";
pub const SECURITY_TEST_CONTRACT_ADDRESS: &str = "0x300";
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
// TODO(Adi, 15/01/2023): Remove and compute the class hash corresponding to the ERC20 contract in
// starkgate once we use the real ERC20 contract.
pub const TEST_ERC20_CONTRACT_CLASS_HASH: &str = "0x1010";
pub const TEST_PAIR_SKELETON_CONTRACT_CLASS_HASH: &str = "0x1011";

// Paths.
pub const ACCOUNT_CONTRACT_CAIRO1_PATH: &str =
    "./feature_contracts/cairo1/compiled/account_contract.casm.json";
pub const ACCOUNT_CONTRACT_CAIRO0_PATH: &str =
    "./feature_contracts/cairo0/compiled/account_without_validations_compiled.json";
pub const TEST_CONTRACT_CAIRO0_PATH: &str =
    "./feature_contracts/cairo0/compiled/test_contract_compiled.json";
pub const TEST_CONTRACT_CAIRO1_PATH: &str =
    "./feature_contracts/cairo1/compiled/test_contract.casm.json";
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
pub const MAX_L1_GAS_AMOUNT: u128 = 1000000;
pub const MAX_L1_GAS_PRICE: u128 = DEFAULT_STRK_L1_GAS_PRICE;
pub const MAX_RESOURCE_COMMITMENT: u128 = MAX_L1_GAS_AMOUNT * MAX_L1_GAS_PRICE;
pub const MAX_FEE: u128 = MAX_L1_GAS_AMOUNT * DEFAULT_ETH_L1_GAS_PRICE;

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
    ])
}

fn get_address_to_v0_class_hash() -> HashMap<ContractAddress, ClassHash> {
    // Two instances of a test contract, one instance of another test contract and a pair contract.
    HashMap::from([
        (contract_address!(TEST_CONTRACT_ADDRESS), class_hash!(TEST_CLASS_HASH)),
        (contract_address!(TEST_CONTRACT_ADDRESS_2), class_hash!(TEST_CLASS_HASH)),
        (contract_address!(SECURITY_TEST_CONTRACT_ADDRESS), class_hash!(SECURITY_TEST_CLASS_HASH)),
        (
            contract_address!(TEST_PAIR_SKELETON_CONTRACT_ADDRESS1),
            class_hash!(TEST_PAIR_SKELETON_CONTRACT_CLASS_HASH),
        ),
    ])
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
    ])
}

pub fn deprecated_create_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = get_class_hash_to_v0_class_mapping();
    let address_to_class_hash = get_address_to_v0_class_hash();
    let storage_view = get_storage_values_for_deprecated_test_state();

    CachedState::from(DictStateReader {
        class_hash_to_class,
        address_to_class_hash,
        storage_view,
        ..Default::default()
    })
}

pub fn create_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = get_class_hash_to_v1_class_mapping();

    // Two instances of a test contract and one instance of another (different) test contract.
    let address_to_class_hash = HashMap::from([
        (contract_address!(TEST_CONTRACT_ADDRESS), class_hash!(TEST_CLASS_HASH)),
        (contract_address!(TEST_CONTRACT_ADDRESS_2), class_hash!(TEST_CLASS_HASH)),
        (
            contract_address!(TEST_PAIR_SKELETON_CONTRACT_ADDRESS1),
            class_hash!(TEST_PAIR_SKELETON_CONTRACT_CLASS_HASH),
        ),
    ]);

    CachedState::from(DictStateReader {
        class_hash_to_class,
        address_to_class_hash,
        ..Default::default()
    })
}

fn create_deploy_test_state_from_classes(
    class_hash_to_class: ContractClassMapping,
) -> CachedState<DictStateReader> {
    let class_hash = class_hash!(TEST_CLASS_HASH);
    let contract_address = contract_address!(TEST_CONTRACT_ADDRESS);
    let another_contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &calldata![
            stark_felt!(3_u8), // Calldata: address.
            stark_felt!(3_u8)  // Calldata: value.
        ],
        contract_address!(TEST_CONTRACT_ADDRESS),
    )
    .unwrap();
    let address_to_class_hash =
        HashMap::from([(contract_address, class_hash), (another_contract_address, class_hash)]);

    CachedState::from(DictStateReader {
        class_hash_to_class,
        address_to_class_hash,
        ..Default::default()
    })
}

pub fn deprecated_create_deploy_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = get_class_hash_to_v0_class_mapping();
    create_deploy_test_state_from_classes(class_hash_to_class)
}

pub fn create_deploy_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = get_class_hash_to_v1_class_mapping();
    create_deploy_test_state_from_classes(class_hash_to_class)
}

impl CallEntryPoint {
    /// Executes the call directly, without account context.
    // TODO(Nir, 01/11/2023): adjust to V3, context as an arg or testing mode (<V3, V3).
    pub fn execute_directly(self, state: &mut dyn State) -> EntryPointExecutionResult<CallInfo> {
        let block_context = BlockContext::create_for_testing();
        let mut context = EntryPointExecutionContext::new_invoke(
            &block_context,
            &AccountTransactionContext::Deprecated(DeprecatedAccountTransactionContext::default()),
        );
        self.execute(state, &mut ExecutionResources::default(), &mut context)
    }
    /// Executes the call directly in validate mode, without account context.
    pub fn execute_directly_in_validate_mode(
        self,
        state: &mut dyn State,
    ) -> EntryPointExecutionResult<CallInfo> {
        let block_context = BlockContext::create_for_testing();
        let mut context = EntryPointExecutionContext::new_validate(
            &block_context,
            &AccountTransactionContext::Deprecated(DeprecatedAccountTransactionContext::default()),
        );
        self.execute(state, &mut ExecutionResources::default(), &mut context)
    }
}

impl BlockContext {
    pub fn create_for_testing() -> BlockContext {
        BlockContext {
            chain_id: ChainId(CHAIN_ID_NAME.to_string()),
            block_number: BlockNumber(CURRENT_BLOCK_NUMBER),
            block_timestamp: BlockTimestamp(CURRENT_BLOCK_TIMESTAMP),
            sequencer_address: contract_address!(TEST_SEQUENCER_ADDRESS),
            fee_token_addresses: FeeTokenAddresses {
                eth_fee_token_address: contract_address!(TEST_ERC20_CONTRACT_ADDRESS),
                strk_fee_token_address: contract_address!(TEST_ERC20_CONTRACT_ADDRESS2),
            },
            vm_resource_fee_cost: Default::default(),
            gas_prices: GasPrices {
                eth_l1_gas_price: DEFAULT_ETH_L1_GAS_PRICE,
                strk_l1_gas_price: DEFAULT_STRK_L1_GAS_PRICE,
            },
            invoke_tx_max_n_steps: MAX_STEPS_PER_TX as u32,
            validate_max_n_steps: MAX_VALIDATE_STEPS_PER_TX as u32,
            max_recursion_depth: 50,
        }
    }

    pub fn create_for_account_testing() -> BlockContext {
        let vm_resource_fee_cost = Arc::new(HashMap::from([
            (constants::N_STEPS_RESOURCE.to_string(), 1_f64),
            (HASH_BUILTIN_NAME.to_string(), 1_f64),
            (RANGE_CHECK_BUILTIN_NAME.to_string(), 1_f64),
            (SIGNATURE_BUILTIN_NAME.to_string(), 1_f64),
            (BITWISE_BUILTIN_NAME.to_string(), 1_f64),
            (POSEIDON_BUILTIN_NAME.to_string(), 1_f64),
            (OUTPUT_BUILTIN_NAME.to_string(), 1_f64),
            (EC_OP_BUILTIN_NAME.to_string(), 1_f64),
        ]));
        BlockContext { vm_resource_fee_cost, ..BlockContext::create_for_testing() }
    }
}

impl CallExecution {
    pub fn from_retdata(retdata: Retdata) -> Self {
        Self { retdata, ..Default::default() }
    }
}

// Transactions.
#[derive(Clone)]
pub struct InvokeTxArgs {
    pub max_fee: Fee,
    pub signature: TransactionSignature,
    pub sender_address: ContractAddress,
    pub calldata: Calldata,
    pub version: TransactionVersion,
    pub resource_bounds: ResourceBoundsMapping,
    pub tip: Tip,
    pub nonce_data_availability_mode: DataAvailabilityMode,
    pub fee_data_availability_mode: DataAvailabilityMode,
    pub paymaster_data: PaymasterData,
    pub account_deployment_data: AccountDeploymentData,
    pub nonce: Nonce,
}

impl Default for InvokeTxArgs {
    fn default() -> Self {
        InvokeTxArgs {
            max_fee: Fee::default(),
            signature: TransactionSignature::default(),
            sender_address: ContractAddress::default(),
            calldata: calldata![],
            // TODO(Dori, 10/10/2023): Change to THREE when supported.
            version: TransactionVersion::ONE,
            // TODO(Dori, 1/11/2023): Once `From` is implemented on `ResourceBoundsMapping`, use it.
            resource_bounds: ResourceBoundsMapping(BTreeMap::from([
                (Resource::L1Gas, ResourceBounds { max_amount: 0, max_price_per_unit: 1 }),
                // TODO(Dori, 1/2/2024): When fee market is developed, change the default price of
                //   L2 gas.
                (Resource::L2Gas, ResourceBounds { max_amount: 0, max_price_per_unit: 0 }),
            ])),
            tip: Tip::default(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            paymaster_data: PaymasterData::default(),
            account_deployment_data: AccountDeploymentData::default(),
            nonce: Nonce::default(),
        }
    }
}

/// Utility macro for creating `InvokeTxArgs` with "smart" default values, kwarg-style notation.
#[macro_export]
macro_rules! invoke_tx_args {
    ($($field:ident $(: $value:expr)?),* $(,)?) => {
        {
            // Fill in all fields + defaults for missing fields.
            let mut _macro_invoke_tx_args = InvokeTxArgs {
                $($field $(: $value)?,)*
                ..Default::default()
            };
            // If resource bounds aren't explicitly passed, derive them from max_fee.
            if _macro_invoke_tx_args.version >= TransactionVersion::THREE
                && [$(stringify!($field) != "resource_bounds"),*].iter().all(|&x| x) {
                // TODO(Dori, 1/11/2023): When `ResourceBoundsMapping` implements `TryFrom`, use it.
                for resource in [
                    starknet_api::transaction::Resource::L1Gas,
                    starknet_api::transaction::Resource::L2Gas
                ].into_iter() {
                    _macro_invoke_tx_args.resource_bounds.0.insert(
                        resource,
                        starknet_api::transaction::ResourceBounds {
                            max_amount: _macro_invoke_tx_args.max_fee.0 as u64,
                            max_price_per_unit: 1
                        },
                    );
                }
            }
            _macro_invoke_tx_args
        }
    };
    ($($field:ident $(: $value:expr)?),* , ..$defaults:expr) => {
        {
            // Fill in all fields + use the provided defaults for missing fields.
            // In this case, do not derive "smart" defaults for fields not passed explicitly - we
            // assume these fields are already "correct" on the provided defaults.
            InvokeTxArgs {
                $($field $(: $value)?,)*
                ..$defaults
            }
        }
    };
}

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

    DeployAccountTransaction { tx, tx_hash: TransactionHash::default(), contract_address }
}

pub fn invoke_tx(invoke_args: InvokeTxArgs) -> InvokeTransaction {
    match invoke_args.version {
        TransactionVersion::ZERO => InvokeTransactionV0 {
            max_fee: invoke_args.max_fee,
            calldata: invoke_args.calldata,
            contract_address: invoke_args.sender_address,
            signature: invoke_args.signature,
            // V0 transactions should always select the `__execute__` entry point.
            entry_point_selector: selector_from_name(EXECUTE_ENTRY_POINT_NAME),
        }
        .into(),
        TransactionVersion::ONE => InvokeTransactionV1 {
            max_fee: invoke_args.max_fee,
            sender_address: invoke_args.sender_address,
            nonce: invoke_args.nonce,
            calldata: invoke_args.calldata,
            signature: invoke_args.signature,
        }
        .into(),
        TransactionVersion::THREE => InvokeTransactionV3 {
            resource_bounds: invoke_args.resource_bounds,
            calldata: invoke_args.calldata,
            sender_address: invoke_args.sender_address,
            nonce: invoke_args.nonce,
            signature: invoke_args.signature,
            tip: invoke_args.tip,
            nonce_data_availability_mode: invoke_args.nonce_data_availability_mode,
            fee_data_availability_mode: invoke_args.fee_data_availability_mode,
            paymaster_data: invoke_args.paymaster_data,
            account_deployment_data: invoke_args.account_deployment_data,
        }
        .into(),
        _ => panic!("Unsupported transaction version: {:?}.", invoke_args.version),
    }
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

// Contract loaders.

impl ContractClassV0 {
    pub fn from_file(contract_path: &str) -> ContractClassV0 {
        let raw_contract_class = get_raw_contract_class(contract_path);
        Self::try_from_json_string(&raw_contract_class).unwrap()
    }
}

impl ContractClassV1 {
    pub fn from_file(contract_path: &str) -> ContractClassV1 {
        let raw_contract_class = get_raw_contract_class(contract_path);
        Self::try_from_json_string(&raw_contract_class).unwrap()
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
