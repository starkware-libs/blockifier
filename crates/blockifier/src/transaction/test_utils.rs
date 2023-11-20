use std::collections::HashMap;

use starknet_api::core::{ClassHash, ContractAddress, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, Fee, InvokeTransactionV0, InvokeTransactionV1, InvokeTransactionV3, Resource,
    ResourceBounds, ResourceBoundsMapping, TransactionHash, TransactionSignature,
    TransactionVersion,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};

use crate::abi::abi_utils::get_storage_var_address;
use crate::block_context::BlockContext;
use crate::execution::contract_class::{ContractClass, ContractClassV0, ContractClassV1};
use crate::invoke_tx_args;
use crate::state::cached_state::CachedState;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::invoke::{invoke_tx, InvokeTxArgs};
use crate::test_utils::{
    create_calldata, test_erc20_account_balance_key, test_erc20_faulty_account_balance_key,
    NonceManager, ACCOUNT_CONTRACT_CAIRO0_PATH, ACCOUNT_CONTRACT_CAIRO1_PATH, BALANCE,
    ERC20_CONTRACT_PATH, TEST_ACCOUNT_CONTRACT_ADDRESS, TEST_ACCOUNT_CONTRACT_CLASS_HASH,
    TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS, TEST_CONTRACT_CAIRO0_PATH,
    TEST_ERC20_CONTRACT_CLASS_HASH, TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS,
    TEST_FAULTY_ACCOUNT_CONTRACT_CAIRO0_PATH, TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants;
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transactions::{
    DeclareTransaction, ExecutableTransaction, InvokeTransaction,
};

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

pub fn create_account_tx_for_validate_test(
    tx_type: TransactionType,
    scenario: u64,
    additional_data: Option<StarkFelt>,
    nonce_manager: &mut NonceManager,
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
            let contract_class =
                ContractClassV0::from_file(TEST_FAULTY_ACCOUNT_CONTRACT_CAIRO0_PATH).into();
            let declare_tx = crate::test_utils::declare_tx(
                TEST_ACCOUNT_CONTRACT_CLASS_HASH,
                contract_address!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS),
                Fee(0),
                Some(signature),
            );

            AccountTransaction::Declare(
                DeclareTransaction::new(
                    starknet_api::transaction::DeclareTransaction::V1(declare_tx),
                    TransactionHash::default(),
                    contract_class,
                )
                .unwrap(),
            )
        }
        TransactionType::DeployAccount => {
            let deploy_account_tx = crate::test_utils::deploy_account::deploy_account_tx(
                TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH,
                Fee(0),
                Some(calldata![stark_felt!(constants::FELT_FALSE)]),
                Some(signature),
                nonce_manager,
            );
            AccountTransaction::DeployAccount(deploy_account_tx)
        }
        TransactionType::InvokeFunction => {
            let execute_calldata = create_calldata(
                contract_address!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS),
                "foo",
                &[],
            );
            let invoke_tx = crate::test_utils::invoke::invoke_tx(invoke_tx_args! {
                signature,
                sender_address: contract_address!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS),
                calldata: execute_calldata,
                version: TransactionVersion::ONE,
                nonce: Nonce::default(),
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
