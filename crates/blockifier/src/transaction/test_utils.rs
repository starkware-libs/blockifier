use std::collections::HashMap;

use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Calldata, Fee, InvokeTransaction, TransactionSignature};
use starknet_api::{calldata, patricia_key, stark_felt};

use super::account_transaction::AccountTransaction;
use super::transaction_types::TransactionType;
use crate::abi::abi_utils::{get_storage_var_address, selector_from_name};
use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClassV0;
use crate::state::cached_state::CachedState;
use crate::test_utils::{
    test_erc20_account_balance_key, test_erc20_faulty_account_balance_key, DictStateReader,
    NonceManager, ACCOUNT_CONTRACT_PATH, BALANCE, ERC20_CONTRACT_PATH,
    TEST_ACCOUNT_CONTRACT_ADDRESS, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH,
    TEST_CONTRACT_ADDRESS, TEST_CONTRACT_PATH, TEST_ERC20_CONTRACT_CLASS_HASH,
    TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS, TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH,
    TEST_FAULTY_ACCOUNT_CONTRACT_PATH,
};
use crate::transaction::constants;
use crate::transaction::transactions::DeclareTransaction;

// Corresponding constants to the ones in faulty_account.
pub const VALID: u64 = 0;
pub const INVALID: u64 = 1;
pub const CALL_CONTRACT: u64 = 2;

pub fn create_account_tx_test_state(
    account_class_hash: &str,
    account_address: &str,
    account_path: &str,
    erc20_account_balance_key: StorageKey,
    initial_account_balance: u128,
) -> CachedState<DictStateReader> {
    let block_context = BlockContext::create_for_testing();

    let test_contract_class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    let test_account_class_hash = ClassHash(stark_felt!(account_class_hash));
    let test_erc20_class_hash = ClassHash(stark_felt!(TEST_ERC20_CONTRACT_CLASS_HASH));
    let class_hash_to_class = HashMap::from([
        (test_account_class_hash, ContractClassV0::from_file(account_path).into()),
        (test_contract_class_hash, ContractClassV0::from_file(TEST_CONTRACT_PATH).into()),
        (test_erc20_class_hash, ContractClassV0::from_file(ERC20_CONTRACT_PATH).into()),
    ]);
    let test_contract_address = ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS));
    // A random address that is unlikely to equal the result of the calculation of a contract
    // address.
    let test_account_address = ContractAddress(patricia_key!(account_address));
    let test_erc20_address = block_context.fee_token_address;
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
    CachedState::new(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        storage_view,
        ..Default::default()
    })
}

pub fn create_state_with_trivial_validation_account() -> CachedState<DictStateReader> {
    let account_balance = BALANCE;
    create_account_tx_test_state(
        TEST_ACCOUNT_CONTRACT_CLASS_HASH,
        TEST_ACCOUNT_CONTRACT_ADDRESS,
        ACCOUNT_CONTRACT_PATH,
        test_erc20_account_balance_key(),
        account_balance,
    )
}

pub fn create_state_with_falliable_validation_account() -> CachedState<DictStateReader> {
    let account_balance = BALANCE;
    create_account_tx_test_state(
        TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH,
        TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS,
        TEST_FAULTY_ACCOUNT_CONTRACT_PATH,
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
                ContractClassV0::from_file(TEST_FAULTY_ACCOUNT_CONTRACT_PATH).into();
            let declare_tx = crate::test_utils::declare_tx(
                TEST_ACCOUNT_CONTRACT_CLASS_HASH,
                ContractAddress(patricia_key!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS)),
                Fee(0),
                Some(signature),
            );

            AccountTransaction::Declare(
                DeclareTransaction::new(
                    starknet_api::transaction::DeclareTransaction::V1(declare_tx),
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
                ContractAddress(patricia_key!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS)),
                Fee(0),
                Some(signature),
            );
            AccountTransaction::Invoke(InvokeTransaction::V1(invoke_tx))
        }
        TransactionType::L1Handler => unimplemented!(),
    }
}
