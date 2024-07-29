use rstest::fixture;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, Fee, InvokeTransactionV0, InvokeTransactionV1,
    InvokeTransactionV3, Resource, ResourceBounds, ResourceBoundsMapping, TransactionHash,
    TransactionSignature, TransactionVersion,
};
use starknet_api::{calldata, stark_felt};
use strum::IntoEnumIterator;

use crate::abi::abi_utils::get_fee_token_var_address;
use crate::context::{BlockContext, ChainInfo};
use crate::execution::contract_class::{ClassInfo, ContractClass};
use crate::state::cached_state::CachedState;
use crate::state::state_api::State;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::declare::declare_tx;
use crate::test_utils::deploy_account::{deploy_account_tx, DeployAccountTxArgs};
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::invoke::{invoke_tx, InvokeTxArgs};
use crate::test_utils::{
    create_calldata, CairoVersion, NonceManager, BALANCE, MAX_FEE, MAX_L1_GAS_AMOUNT,
    MAX_L1_GAS_PRICE,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants;
use crate::transaction::objects::{FeeType, TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transactions::{ExecutableTransaction, InvokeTransaction};
use crate::{declare_tx_args, deploy_account_tx_args, invoke_tx_args};

// Corresponding constants to the ones in faulty_account.
pub const VALID: u64 = 0;
pub const INVALID: u64 = 1;
pub const CALL_CONTRACT: u64 = 2;
pub const GET_BLOCK_HASH: u64 = 3;
pub const GET_EXECUTION_INFO: u64 = 4;
pub const GET_BLOCK_NUMBER: u64 = 5;
pub const GET_BLOCK_TIMESTAMP: u64 = 6;
pub const GET_SEQUENCER_ADDRESS: u64 = 7;

macro_rules! impl_from_versioned_tx {
    ($(($specified_tx_type:ty, $enum_variant:ident)),*) => {
        $(impl From<$specified_tx_type> for InvokeTransaction {
            fn from(tx: $specified_tx_type) -> Self {
                Self::new(
                    starknet_api::transaction::InvokeTransaction::$enum_variant(tx),
                    TransactionHash::default(),
                )
            }
        })*
    };
}

impl_from_versioned_tx!(
    (InvokeTransactionV0, V0),
    (InvokeTransactionV1, V1),
    (InvokeTransactionV3, V3)
);

/// Test fixtures.

#[fixture]
pub fn max_fee() -> Fee {
    Fee(MAX_FEE)
}

#[fixture]
pub fn max_resource_bounds() -> ResourceBoundsMapping {
    l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE)
}

#[fixture]
pub fn block_context() -> BlockContext {
    BlockContext::create_for_account_testing()
}

/// Struct containing the data usually needed to initialize a test.
pub struct TestInitData {
    pub state: CachedState<DictStateReader>,
    pub account_address: ContractAddress,
    pub contract_address: ContractAddress,
    pub nonce_manager: NonceManager,
}

/// Deploys a new account with the given class hash, funds with both fee tokens, and returns the
/// deploy tx and address.
pub fn deploy_and_fund_account(
    state: &mut CachedState<DictStateReader>,
    nonce_manager: &mut NonceManager,
    chain_info: &ChainInfo,
    deploy_tx_args: DeployAccountTxArgs,
) -> (AccountTransaction, ContractAddress) {
    // Deploy an account contract.
    let deploy_account_tx = deploy_account_tx(deploy_tx_args, nonce_manager);
    let account_address = deploy_account_tx.contract_address;
    let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);

    // Update the balance of the about-to-be deployed account contract in the erc20 contract, so it
    // can pay for the transaction execution.
    // Set balance in all fee types.
    let deployed_account_balance_key = get_fee_token_var_address(account_address);
    for fee_type in FeeType::iter() {
        let fee_token_address = chain_info.fee_token_address(&fee_type);
        state
            .set_storage_at(fee_token_address, deployed_account_balance_key, stark_felt!(BALANCE))
            .unwrap();
    }

    (account_tx, account_address)
}

/// Initializes a state and returns a `TestInitData` instance.
pub fn create_test_init_data(chain_info: &ChainInfo, cairo_version: CairoVersion) -> TestInitData {
    let account = FeatureContract::AccountWithoutValidations(cairo_version);
    let test_contract = FeatureContract::TestContract(cairo_version);
    let erc20 = FeatureContract::ERC20;
    let state = test_state(chain_info, BALANCE, &[(account, 1), (erc20, 1), (test_contract, 1)]);
    TestInitData {
        state,
        account_address: account.get_instance_address(0),
        contract_address: test_contract.get_instance_address(0),
        nonce_manager: NonceManager::default(),
    }
}

pub struct FaultyAccountTxCreatorArgs {
    pub tx_type: TransactionType,
    pub tx_version: TransactionVersion,
    pub scenario: u64,
    pub max_fee: Fee,
    // Should be None unless scenario is CALL_CONTRACT.
    pub additional_data: Option<Vec<StarkFelt>>,
    // Should be use with tx_type Declare or InvokeFunction.
    pub sender_address: ContractAddress,
    // Should be used with tx_type DeployAccount.
    pub class_hash: ClassHash,
    // Should be used with tx_type DeployAccount.
    pub contract_address_salt: ContractAddressSalt,
    // Should be used with tx_type DeployAccount.
    pub validate_constructor: bool,
    // Should be used with tx_type Declare.
    pub declared_contract: Option<FeatureContract>,
}

impl Default for FaultyAccountTxCreatorArgs {
    fn default() -> Self {
        Self {
            tx_type: TransactionType::InvokeFunction,
            tx_version: TransactionVersion::THREE,
            scenario: VALID,
            additional_data: None,
            sender_address: ContractAddress::default(),
            class_hash: ClassHash::default(),
            contract_address_salt: ContractAddressSalt::default(),
            validate_constructor: false,
            max_fee: Fee::default(),
            declared_contract: None,
        }
    }
}

/// Creates an account transaction to test the 'validate' method of account transactions. These
/// transactions should be used for unit tests. For example, it is not intended to deploy a contract
/// and later call it.
pub fn create_account_tx_for_validate_test(
    nonce_manager: &mut NonceManager,
    faulty_account_tx_creator_args: FaultyAccountTxCreatorArgs,
) -> AccountTransaction {
    let FaultyAccountTxCreatorArgs {
        tx_type,
        tx_version,
        scenario,
        additional_data,
        sender_address,
        class_hash,
        contract_address_salt,
        validate_constructor,
        max_fee,
        declared_contract,
    } = faulty_account_tx_creator_args;

    // The first felt of the signature is used to set the scenario. If the scenario is
    // `CALL_CONTRACT` the second felt is used to pass the contract address.
    let mut signature_vector = vec![StarkFelt::from(scenario)];
    if let Some(additional_data) = additional_data {
        signature_vector.extend(additional_data);
    }
    let signature = TransactionSignature(signature_vector);

    match tx_type {
        TransactionType::Declare => {
            let declared_contract = match declared_contract {
                Some(declared_contract) => declared_contract,
                None => {
                    // It does not matter which class is declared for this test.
                    FeatureContract::TestContract(CairoVersion::from_declare_tx_version(tx_version))
                }
            };
            let class_hash = declared_contract.get_class_hash();
            let class_info = calculate_class_info_for_testing(declared_contract.get_class());
            declare_tx(
                declare_tx_args! {
                    max_fee,
                    signature,
                    sender_address,
                    version: tx_version,
                    nonce: nonce_manager.next(sender_address),
                    class_hash,
                },
                class_info,
            )
        }
        TransactionType::DeployAccount => {
            // We do not use the sender address here because the transaction generates the actual
            // sender address.
            let constructor_calldata = calldata![stark_felt!(match validate_constructor {
                true => constants::FELT_TRUE,
                false => constants::FELT_FALSE,
            })];
            let deploy_account_tx = deploy_account_tx(
                deploy_account_tx_args! {
                    max_fee,
                    signature,
                    version: tx_version,
                    class_hash,
                    contract_address_salt,
                    constructor_calldata,
                },
                nonce_manager,
            );
            AccountTransaction::DeployAccount(deploy_account_tx)
        }
        TransactionType::InvokeFunction => {
            let execute_calldata = create_calldata(sender_address, "foo", &[]);
            let invoke_tx = invoke_tx(invoke_tx_args! {
                max_fee,
                signature,
                sender_address,
                calldata: execute_calldata,
                version: tx_version,
                nonce: nonce_manager.next(sender_address),
            });
            AccountTransaction::Invoke(invoke_tx)
        }
        _ => panic!("{tx_type:?} is not an account transaction."),
    }
}

pub fn account_invoke_tx(invoke_args: InvokeTxArgs) -> AccountTransaction {
    AccountTransaction::Invoke(invoke_tx(invoke_args))
}

pub fn run_invoke_tx(
    state: &mut CachedState<DictStateReader>,
    block_context: &BlockContext,
    invoke_args: InvokeTxArgs,
) -> TransactionExecutionResult<TransactionExecutionInfo> {
    account_invoke_tx(invoke_args).execute(state, block_context, true, true)
}

/// Creates a `ResourceBoundsMapping` with the given `max_amount` and `max_price` for L1 gas limits.
/// No guarantees on the values of the other resources bounds.
pub fn l1_resource_bounds(max_amount: u64, max_price: u128) -> ResourceBoundsMapping {
    ResourceBoundsMapping::try_from(vec![
        (Resource::L1Gas, ResourceBounds { max_amount, max_price_per_unit: max_price }),
        (Resource::L2Gas, ResourceBounds { max_amount: 0, max_price_per_unit: 0 }),
    ])
    .unwrap()
}

pub fn calculate_class_info_for_testing(contract_class: ContractClass) -> ClassInfo {
    let sierra_program_length = match contract_class {
        ContractClass::V0(_) => 0,
        ContractClass::V1(_) => 100,
        ContractClass::V1Native(_) => todo!("should this also be 100?"),
    };
    ClassInfo::new(&contract_class, sierra_program_length, 100).unwrap()
}

pub fn emit_n_events_tx(
    n: usize,
    account_contract: ContractAddress,
    contract_address: ContractAddress,
    nonce: Nonce,
) -> AccountTransaction {
    let entry_point_args = vec![
        stark_felt!(u32::try_from(n).unwrap()), // events_number.
        stark_felt!(0_u32),                     // keys length.
        stark_felt!(0_u32),                     // data length.
    ];
    let calldata = create_calldata(contract_address, "test_emit_events", &entry_point_args);
    account_invoke_tx(invoke_tx_args! {
        sender_address: account_contract,
        calldata,
        version: TransactionVersion::THREE,
        nonce
    })
}
