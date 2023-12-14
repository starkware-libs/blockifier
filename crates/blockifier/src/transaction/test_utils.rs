use std::collections::HashMap;

use rstest::fixture;
use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, Fee, InvokeTransactionV0, InvokeTransactionV1,
    InvokeTransactionV3, Resource, ResourceBounds, ResourceBoundsMapping, TransactionHash,
    TransactionSignature, TransactionVersion,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};
use strum::IntoEnumIterator;

use crate::abi::abi_utils::{get_fee_token_var_address, get_storage_var_address};
use crate::block_context::BlockContext;
use crate::execution::contract_class::{ContractClass, ContractClassV0, ContractClassV1};
use crate::state::cached_state::CachedState;
use crate::state::state_api::State;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::declare::declare_tx;
use crate::test_utils::deploy_account::{deploy_account_tx, DeployAccountTxArgs};
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::invoke::{invoke_tx, InvokeTxArgs};
use crate::test_utils::{
    create_calldata, test_erc20_account_balance_key, test_erc20_faulty_account_balance_key,
    CairoVersion, NonceManager, ACCOUNT_CONTRACT_CAIRO0_PATH, ACCOUNT_CONTRACT_CAIRO1_PATH,
    BALANCE, ERC20_CONTRACT_PATH, GRINDY_ACCOUNT_CONTRACT_CAIRO0_PATH,
    GRINDY_ACCOUNT_CONTRACT_CAIRO1_PATH, MAX_FEE, MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE,
    TEST_ACCOUNT_CONTRACT_ADDRESS, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH,
    TEST_CONTRACT_ADDRESS, TEST_CONTRACT_CAIRO0_PATH, TEST_ERC20_CONTRACT_CLASS_HASH,
    TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS, TEST_FAULTY_ACCOUNT_CONTRACT_CAIRO0_PATH,
    TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH, TEST_GRINDY_ACCOUNT_CONTRACT_CLASS_HASH_CAIRO0,
    TEST_GRINDY_ACCOUNT_CONTRACT_CLASS_HASH_CAIRO1,
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
    pub block_context: BlockContext,
}

/// Deploys a new account with the given class hash, funds with both fee tokens, and returns the
/// deploy tx and address.
pub fn deploy_and_fund_account(
    state: &mut CachedState<DictStateReader>,
    nonce_manager: &mut NonceManager,
    block_context: &BlockContext,
    deploy_tx_args: DeployAccountTxArgs,
) -> (AccountTransaction, ContractAddress) {
    // Deploy an account contract.
    let deploy_account_tx = deploy_account_tx(deploy_tx_args, nonce_manager);
    let account_address = deploy_account_tx.contract_address;
    let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);

    // Update the balance of the about-to-be deployed account contract in the erc20 contract, so it
    // can pay for the transaction execution.
    // Set balance in all fee types.
    let deployed_account_balance_key = get_fee_token_var_address(&account_address);
    for fee_type in FeeType::iter() {
        let fee_token_address = block_context.fee_token_address(&fee_type);
        state.set_storage_at(fee_token_address, deployed_account_balance_key, stark_felt!(BALANCE));
    }

    (account_tx, account_address)
}

/// Sets up account and test contracts ("declare" + "deploy").
pub fn create_state(block_context: BlockContext) -> CachedState<DictStateReader> {
    // Declare all the needed contracts.
    let test_account_class_hash = class_hash!(TEST_ACCOUNT_CONTRACT_CLASS_HASH);
    let test_grindy_validate_account_class_hash_cairo0 =
        class_hash!(TEST_GRINDY_ACCOUNT_CONTRACT_CLASS_HASH_CAIRO0);
    let test_grindy_validate_account_class_hash_cairo1 =
        class_hash!(TEST_GRINDY_ACCOUNT_CONTRACT_CLASS_HASH_CAIRO1);
    let test_erc20_class_hash = class_hash!(TEST_ERC20_CONTRACT_CLASS_HASH);
    let class_hash_to_class = HashMap::from([
        (test_account_class_hash, ContractClassV0::from_file(ACCOUNT_CONTRACT_CAIRO0_PATH).into()),
        (
            test_grindy_validate_account_class_hash_cairo0,
            ContractClassV0::from_file(GRINDY_ACCOUNT_CONTRACT_CAIRO0_PATH).into(),
        ),
        (
            test_grindy_validate_account_class_hash_cairo1,
            ContractClassV1::from_file(GRINDY_ACCOUNT_CONTRACT_CAIRO1_PATH).into(),
        ),
        (test_erc20_class_hash, ContractClassV0::from_file(ERC20_CONTRACT_PATH).into()),
    ]);
    // Deploy the erc20 contracts.
    let test_eth_address = block_context.fee_token_addresses.eth_fee_token_address;
    let test_strk_address = block_context.fee_token_addresses.strk_fee_token_address;
    let address_to_class_hash = HashMap::from([
        (test_eth_address, test_erc20_class_hash),
        (test_strk_address, test_erc20_class_hash),
    ]);

    CachedState::from(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        ..Default::default()
    })
}

/// Given a partially initialized state, deploys and funds an account, and declares and deploys a
/// test contract.
pub fn create_test_init_data(max_fee: Fee, block_context: BlockContext) -> TestInitData {
    let mut state = create_state(block_context.clone());
    let mut nonce_manager = NonceManager::default();

    let (account_tx, account_address) = deploy_and_fund_account(
        &mut state,
        &mut nonce_manager,
        &block_context,
        deploy_account_tx_args! {
            class_hash: class_hash!(TEST_ACCOUNT_CONTRACT_CLASS_HASH),
            max_fee,
        },
    );
    account_tx.execute(&mut state, &block_context, true, true).unwrap();

    // Declare a contract.
    let contract_class = ContractClassV0::from_file(TEST_CONTRACT_CAIRO0_PATH).into();
    let account_tx = declare_tx(
        declare_tx_args! {
            class_hash: class_hash!(TEST_CLASS_HASH),
            sender_address: account_address,
            max_fee,
            nonce: nonce_manager.next(account_address),
        },
        contract_class,
    );
    account_tx.execute(&mut state, &block_context, true, true).unwrap();

    // Deploy a contract using syscall deploy.
    let salt = ContractAddressSalt::default();
    let class_hash = class_hash!(TEST_CLASS_HASH);
    run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee,
            sender_address: account_address,
            calldata: create_calldata(
                account_address,
                "deploy_contract",
                &[
                class_hash.0,             // Calldata: class_hash.
                salt.0,                   // Contract_address_salt.
                stark_felt!(2_u8),        // Constructor calldata length.
                stark_felt!(1_u8),        // Constructor calldata: address.
                stark_felt!(1_u8)         // Constructor calldata: value.
                ]
            ),
            version: TransactionVersion::ONE,
            nonce: nonce_manager.next(account_address),
        },
    )
    .unwrap();

    // Calculate the newly deployed contract address
    let contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &calldata![stark_felt!(1_u8), stark_felt!(1_u8)],
        account_address,
    )
    .unwrap();

    TestInitData { state, account_address, contract_address, nonce_manager, block_context }
}

pub fn create_account_tx_test_state(
    account_class: ContractClass,
    account_class_hash: &str,
    account_address: &str,
    erc20_account_balance_key: StorageKey,
    initial_account_balance: u128,
    test_contract_class: ContractClass,
) -> CachedState<DictStateReader> {
    let block_context = BlockContext::create_for_testing();

    let test_contract_class_hash = class_hash!(TEST_CLASS_HASH);
    let test_account_class_hash = class_hash!(account_class_hash);
    let test_erc20_class_hash = class_hash!(TEST_ERC20_CONTRACT_CLASS_HASH);
    let class_hash_to_class = HashMap::from([
        (test_account_class_hash, account_class),
        (test_contract_class_hash, test_contract_class),
        (test_erc20_class_hash, ContractClassV0::from_file(ERC20_CONTRACT_PATH).into()),
    ]);
    let test_contract_address = contract_address!(TEST_CONTRACT_ADDRESS);
    // A random address that is unlikely to equal the result of the calculation of a contract
    // address.
    let test_account_address = contract_address!(account_address);
    let test_strk_token_address = block_context.fee_token_addresses.strk_fee_token_address;
    let test_eth_token_address = block_context.fee_token_addresses.eth_fee_token_address;
    let address_to_class_hash = HashMap::from([
        (test_contract_address, test_contract_class_hash),
        (test_account_address, test_account_class_hash),
        (test_strk_token_address, test_erc20_class_hash),
        (test_eth_token_address, test_erc20_class_hash),
    ]);
    let minter_var_address = get_storage_var_address("permitted_minter", &[]);

    let initial_balance_felt = stark_felt!(initial_account_balance);
    let storage_view = HashMap::from([
        ((test_strk_token_address, erc20_account_balance_key), initial_balance_felt),
        ((test_eth_token_address, erc20_account_balance_key), initial_balance_felt),
        // Give the account mint permission.
        ((test_strk_token_address, minter_var_address), *test_account_address.0.key()),
        ((test_eth_token_address, minter_var_address), *test_account_address.0.key()),
    ]);
    CachedState::from(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        storage_view,
        ..Default::default()
    })
}

pub fn create_state_with_trivial_validation_account() -> CachedState<DictStateReader> {
    let account_balance = BALANCE;
    create_account_tx_test_state(
        ContractClassV0::from_file(ACCOUNT_CONTRACT_CAIRO0_PATH).into(),
        TEST_ACCOUNT_CONTRACT_CLASS_HASH,
        TEST_ACCOUNT_CONTRACT_ADDRESS,
        test_erc20_account_balance_key(),
        account_balance,
        // TODO(Noa,01/12/2023): Use `once_cell::sync::Lazy` to create the contract class.
        ContractClassV0::from_file(TEST_CONTRACT_CAIRO0_PATH).into(),
    )
}

pub fn create_state_with_cairo1_account() -> CachedState<DictStateReader> {
    let account_balance = BALANCE;
    create_account_tx_test_state(
        ContractClassV1::from_file(ACCOUNT_CONTRACT_CAIRO1_PATH).into(),
        TEST_ACCOUNT_CONTRACT_CLASS_HASH,
        TEST_ACCOUNT_CONTRACT_ADDRESS,
        test_erc20_account_balance_key(),
        account_balance,
        // TODO(Mohammad,01/08/2023): Use Cairo 1 test contract.
        // TODO(Noa,01/12/2023): Use `once_cell::sync::Lazy` to create the contract class.
        ContractClassV0::from_file(TEST_CONTRACT_CAIRO0_PATH).into(),
    )
}

pub fn create_state_with_falliable_validation_account() -> CachedState<DictStateReader> {
    let account_balance = BALANCE;
    create_account_tx_test_state(
        ContractClassV0::from_file(TEST_FAULTY_ACCOUNT_CONTRACT_CAIRO0_PATH).into(),
        TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH,
        TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS,
        test_erc20_faulty_account_balance_key(),
        account_balance * 2,
        // TODO(Noa,01/12/2023): Use `once_cell::sync::Lazy` to create the contract class.
        ContractClassV0::from_file(TEST_CONTRACT_CAIRO0_PATH).into(),
    )
}

/// Creates an account transaction to test the 'validate' method of account transactions. These
/// transactions should be used for unit tests. For example, it is not intended to deploy a contract
/// and later call it.
pub fn create_account_tx_for_validate_test(
    tx_type: TransactionType,
    scenario: u64,
    additional_data: Option<StarkFelt>,
    nonce_manager: &mut NonceManager,
    faulty_account: FeatureContract,
    sender_address: ContractAddress,
    contract_address_salt: ContractAddressSalt,
) -> AccountTransaction {
    // The first felt of the signature is used to set the scenario. If the scenario is
    // `CALL_CONTRACT` the second felt is used to pass the contract address.
    let signature = TransactionSignature(vec![
        StarkFelt::from(scenario),
        // Assumes the default value of StarkFelt is 0.
        additional_data.unwrap_or_default(),
    ]);

    match tx_type {
        TransactionType::Declare => {
            // It does not matter which class is declared for this test.
            let declared_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
            let class_hash = declared_contract.get_class_hash();
            let contract_class = declared_contract.get_class();
            declare_tx(
                declare_tx_args! {
                    class_hash,
                    sender_address,
                    signature,
                    nonce: nonce_manager.next(sender_address)
                },
                contract_class,
            )
        }
        TransactionType::DeployAccount => {
            // We do not use the sender address here because the transaction generates the actual
            // sender address.
            let deploy_account_tx = deploy_account_tx(
                deploy_account_tx_args! {
                    class_hash: faulty_account.get_class_hash(),
                    constructor_calldata: calldata![stark_felt!(constants::FELT_FALSE)],
                    signature,
                    contract_address_salt,
                },
                nonce_manager,
            );
            AccountTransaction::DeployAccount(deploy_account_tx)
        }
        TransactionType::InvokeFunction => {
            let execute_calldata = create_calldata(sender_address, "foo", &[]);
            let invoke_tx = invoke_tx(invoke_tx_args! {
                signature,
                sender_address,
                calldata: execute_calldata,
                version: TransactionVersion::ONE,
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
