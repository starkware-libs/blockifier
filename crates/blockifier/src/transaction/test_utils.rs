use std::collections::HashMap;

use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, Fee, InvokeTransactionV1, TransactionHash, TransactionSignature,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};

use crate::abi::abi_utils::{get_storage_var_address, selector_from_name};
use crate::block_context::BlockContext;
use crate::execution::contract_class::{ContractClass, ContractClassV0, ContractClassV1};
use crate::state::cached_state::CachedState;
use crate::test_utils::{
    invoke_tx, test_erc20_account_balance_key, test_erc20_faulty_account_balance_key,
    DictStateReader, NonceManager, ACCOUNT_CONTRACT_CAIRO0_PATH, ACCOUNT_CONTRACT_CAIRO1_PATH,
    BALANCE, ERC20_CONTRACT_PATH, TEST_ACCOUNT_CONTRACT_ADDRESS, TEST_ACCOUNT_CONTRACT_CLASS_HASH,
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

impl From<InvokeTransactionV1> for InvokeTransaction {
    fn from(tx: InvokeTransactionV1) -> Self {
        InvokeTransaction {
            tx: starknet_api::transaction::InvokeTransaction::V1(tx),
            tx_hash: TransactionHash::default(),
        }
    }
}

pub fn create_account_tx_test_state(
    account_class: ContractClass,
    account_class_hash: &str,
    account_address: &str,
    erc20_account_balance_key: StorageKey,
    initial_account_balance: u128,
) -> CachedState<DictStateReader> {
    let block_context = BlockContext::create_for_testing();

    let test_contract_class_hash = class_hash!(TEST_CLASS_HASH);
    let test_account_class_hash = class_hash!(account_class_hash);
    let test_erc20_class_hash = class_hash!(TEST_ERC20_CONTRACT_CLASS_HASH);
    let class_hash_to_class = HashMap::from([
        (test_account_class_hash, account_class),
        // TODO(Mohammad,01/08/2023): Use Cairo 1 test contract when running Cairo 1 account
        // contract.
        (test_contract_class_hash, ContractClassV0::from_file(TEST_CONTRACT_CAIRO0_PATH).into()),
        (test_erc20_class_hash, ContractClassV0::from_file(ERC20_CONTRACT_PATH).into()),
    ]);
    let test_contract_address = contract_address!(TEST_CONTRACT_ADDRESS);
    // A random address that is unlikely to equal the result of the calculation of a contract
    // address.
    let test_account_address = contract_address!(account_address);
    // TODO(Dori, 1/9/2023): NEW_TOKEN_SUPPORT add another fee token to the initial state.
    let test_erc20_address = block_context.deprecated_fee_token_address;
    let address_to_class_hash = HashMap::from([
        (test_contract_address, test_contract_class_hash),
        (test_account_address, test_account_class_hash),
        (test_erc20_address, test_erc20_class_hash),
    ]);
    let minter_var_address = get_storage_var_address("permitted_minter", &[])
        .expect("Failed to get permitted_minter storage address.");
    let storage_view = HashMap::from([
        ((test_erc20_address, erc20_account_balance_key), stark_felt!(initial_account_balance)),
        // Give the account mint permission.
        ((test_erc20_address, minter_var_address), *test_account_address.0.key()),
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
            let deploy_account_tx = crate::test_utils::deploy_account_tx(
                TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH,
                Fee(0),
                Some(calldata![stark_felt!(constants::FELT_FALSE)]),
                Some(signature),
                nonce_manager,
            );
            AccountTransaction::DeployAccount(deploy_account_tx)
        }
        TransactionType::InvokeFunction => {
            let entry_point_selector = selector_from_name("foo");
            let execute_calldata = calldata![
                stark_felt!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS), // Contract address.
                entry_point_selector.0,                            // EP selector.
                stark_felt!(0_u8)                                  // Calldata length.
            ];
            let invoke_tx = crate::test_utils::invoke_tx(
                execute_calldata,
                contract_address!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS),
                Fee(0),
                Some(signature),
            );
            AccountTransaction::Invoke(invoke_tx.into())
        }
        TransactionType::L1Handler => unimplemented!(),
    }
}

pub fn account_invoke_tx(
    execute_calldata: Calldata,
    account_address: ContractAddress,
    nonce_manager: &mut NonceManager,
    max_fee: Fee,
) -> AccountTransaction {
    let tx = invoke_tx(execute_calldata, account_address, max_fee, None);
    AccountTransaction::Invoke(
        InvokeTransactionV1 { nonce: nonce_manager.next(account_address), ..tx }.into(),
    )
}

pub fn run_invoke_tx(
    execute_calldata: Calldata,
    state: &mut CachedState<DictStateReader>,
    account_address: ContractAddress,
    block_context: &BlockContext,
    nonce_manager: &mut NonceManager,
    max_fee: Fee,
) -> TransactionExecutionResult<TransactionExecutionInfo> {
    account_invoke_tx(execute_calldata, account_address, nonce_manager, max_fee).execute(
        state,
        block_context,
        true,
        true,
    )
}
