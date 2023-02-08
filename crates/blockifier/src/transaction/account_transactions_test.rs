use std::collections::HashMap;

use starknet_api::core::{calculate_contract_address, ClassHash, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Calldata, ContractAddressSalt, Fee, InvokeTransaction};
use starknet_api::{calldata, patricia_key, stark_felt};

use crate::abi::abi_utils::selector_from_name;
use crate::block_context::BlockContext;
use crate::state::cached_state::CachedState;
use crate::state::state_api::State;
use crate::test_utils::{
    deploy_account_tx, get_contract_class, invoke_tx, DictStateReader, ACCOUNT_CONTRACT_PATH,
    ERC20_CONTRACT_PATH, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH, TEST_CONTRACT_PATH,
    TEST_ERC20_CONTRACT_CLASS_HASH, TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY,
};
use crate::transaction::account_transaction::AccountTransaction;

// The amount of test-token allocated to the account in this test.
pub const BALANCE: u64 = 1000000 * 100000000000; // 1000000 * min_gas_price.

fn create_state() -> CachedState<DictStateReader> {
    let block_context = BlockContext::create_for_testing();

    // Declare all the needed contracts because currently, Declare Transaction does not affect the
    // state.
    let test_contract_class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    let test_account_class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let test_erc20_class_hash = ClassHash(stark_felt!(TEST_ERC20_CONTRACT_CLASS_HASH));
    let class_hash_to_class = HashMap::from([
        (test_contract_class_hash, get_contract_class(TEST_CONTRACT_PATH)),
        (test_account_class_hash, get_contract_class(ACCOUNT_CONTRACT_PATH)),
        (test_erc20_class_hash, get_contract_class(ERC20_CONTRACT_PATH)),
    ]);
    // Deploy the erc20 contract
    let test_erc20_address = block_context.fee_token_address;
    let address_to_class_hash = HashMap::from([(test_erc20_address, test_erc20_class_hash)]);
    CachedState::new(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        ..Default::default()
    })
}

#[test]
fn test_account_flow_test() {
    let state = &mut create_state();
    let block_context = &BlockContext::create_for_testing();
    let max_fee = Fee(BALANCE as u128);

    // Deploy an account contract.
    let deploy_account_tx = deploy_account_tx(TEST_ACCOUNT_CONTRACT_CLASS_HASH, max_fee);
    let deployed_account_address = deploy_account_tx.contract_address;
    let mut account_tx = AccountTransaction::DeployAccount(deploy_account_tx);

    // Update the balance of the about to be deployed account contract in the erc20 contract, so it
    // can pay for the transaction execution.
    state.set_storage_at(
        block_context.fee_token_address,
        StorageKey(patricia_key!(TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY)),
        stark_felt!(max_fee.0 as u64),
    );

    let (_state_diff, _actual_execution_info) = account_tx.execute(state, block_context).unwrap();

    // Deploy a contract using syscall deploy
    let mut entry_point_selector = selector_from_name("deploy_contract");
    let salt = ContractAddressSalt::default();
    let class_hash = stark_felt!(TEST_CLASS_HASH);
    let mut execute_calldata = calldata![
        *deployed_account_address.0.key(), // Contract address.
        entry_point_selector.0,            // EP selector.
        stark_felt!(5),                    // Calldata length.
        class_hash,                        // Calldata: class_hash.
        salt.0,                            // Contract_address_salt.
        stark_felt!(2),                    // Constructor calldata length.
        stark_felt!(1),                    // Constructor calldata: address.
        stark_felt!(1)                     // Constructor calldata: value.
    ];
    let mut tx = invoke_tx(execute_calldata, deployed_account_address, max_fee);
    account_tx =
        AccountTransaction::Invoke(InvokeTransaction { nonce: Nonce(stark_felt!(1)), ..tx });
    let (_state_diff, _actual_execution_info) = account_tx.execute(state, block_context).unwrap();

    // Invoke a function from the newly deployed contract.
    let contract_address = calculate_contract_address(
        salt,
        ClassHash(class_hash),
        &calldata![stark_felt!(1), stark_felt!(1)],
        deployed_account_address,
    )
    .unwrap();
    entry_point_selector = selector_from_name("return_result");
    execute_calldata = calldata![
        *contract_address.0.key(), // Contract address.
        entry_point_selector.0,    // EP selector.
        stark_felt!(1),            // Calldata length.
        stark_felt!(2)             // Calldata: num.
    ];
    tx = invoke_tx(execute_calldata, deployed_account_address, max_fee);
    account_tx =
        AccountTransaction::Invoke(InvokeTransaction { nonce: Nonce(stark_felt!(2)), ..tx });
    let (_state_diff, _actual_execution_info) = account_tx.execute(state, block_context).unwrap();
}
