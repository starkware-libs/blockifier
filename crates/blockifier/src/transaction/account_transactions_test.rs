use std::collections::HashMap;

use starknet_api::core::{calculate_contract_address, ClassHash, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransaction, Fee, InvokeTransaction,
};
use starknet_api::{calldata, patricia_key, stark_felt};

use crate::abi::abi_utils::selector_from_name;
use crate::block_context::BlockContext;
use crate::state::cached_state::CachedState;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::{
    declare_tx, deploy_account_tx, get_contract_class, invoke_tx, DictStateReader,
    ACCOUNT_CONTRACT_PATH, ERC20_CONTRACT_PATH, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH,
    TEST_CONTRACT_PATH, TEST_ERC20_CONTRACT_CLASS_HASH, TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY,
};
use crate::transaction::account_transaction::AccountTransaction;

// The amount of test-token allocated to the account in this test.
pub const BALANCE: u64 = 1000000 * 100000000000; // 1000000 * min_gas_price.

fn create_state() -> CachedState<DictStateReader> {
    let block_context = BlockContext::create_for_testing();

    // Declare all the needed contracts.
    let test_account_class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let test_erc20_class_hash = ClassHash(stark_felt!(TEST_ERC20_CONTRACT_CLASS_HASH));
    let class_hash_to_class = HashMap::from([
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

    // Update the balance of the about to be deployed account contract in the erc20 contract, so it
    // can pay for the transaction execution.
    state.set_storage_at(
        block_context.fee_token_address,
        StorageKey(patricia_key!(TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY)),
        stark_felt!(max_fee.0 as u64),
    );

    // Deploy an account contract.
    let deploy_account_tx = deploy_account_tx(TEST_ACCOUNT_CONTRACT_CLASS_HASH, max_fee);
    let class_hash = deploy_account_tx.class_hash;
    let deployed_account_address = deploy_account_tx.contract_address;
    let mut account_tx = AccountTransaction::DeployAccount(deploy_account_tx);

    let mut _actual_execution_info = account_tx.execute(state, block_context).unwrap();

    // Verify deployment.
    let mut class_hash_from_state = state.get_class_hash_at(deployed_account_address).unwrap();
    assert_eq!(class_hash_from_state, class_hash);

    // Declare a contract
    let contract_class = get_contract_class(TEST_CONTRACT_PATH);
    let declare_tx = declare_tx(TEST_CLASS_HASH, deployed_account_address, max_fee);
    let declare_class_hash = declare_tx.class_hash;
    account_tx = AccountTransaction::Declare(
        DeclareTransaction { nonce: Nonce(stark_felt!(1)), ..declare_tx },
        contract_class.clone(),
    );
    _actual_execution_info = account_tx.execute(state, block_context).unwrap();

    // Check the class_hash -> contract_class mapping has been updated.
    let contract_class_from_state = state.get_contract_class(&declare_class_hash).unwrap();
    assert_eq!(contract_class_from_state, contract_class);

    // Deploy a contract using syscall deploy
    let mut entry_point_selector = selector_from_name("deploy_contract");
    let salt = ContractAddressSalt::default();
    let class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    let mut execute_calldata = calldata![
        *deployed_account_address.0.key(), // Contract address.
        entry_point_selector.0,            // EP selector.
        stark_felt!(5),                    // Calldata length.
        class_hash.0,                      // Calldata: class_hash.
        salt.0,                            // Contract_address_salt.
        stark_felt!(2),                    // Constructor calldata length.
        stark_felt!(1),                    // Constructor calldata: address.
        stark_felt!(1)                     // Constructor calldata: value.
    ];
    let mut tx = invoke_tx(execute_calldata, deployed_account_address, max_fee);
    account_tx =
        AccountTransaction::Invoke(InvokeTransaction { nonce: Nonce(stark_felt!(2)), ..tx });
    _actual_execution_info = account_tx.execute(state, block_context).unwrap();

    // Verify deployment.
    // Calculate the newly deployed contract address
    let contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &calldata![stark_felt!(1), stark_felt!(1)],
        deployed_account_address,
    )
    .unwrap();
    class_hash_from_state = state.get_class_hash_at(contract_address).unwrap();
    assert_eq!(class_hash_from_state, class_hash);

    // Invoke a function from the newly deployed contract.
    entry_point_selector = selector_from_name("return_result");
    execute_calldata = calldata![
        *contract_address.0.key(), // Contract address.
        entry_point_selector.0,    // EP selector.
        stark_felt!(1),            // Calldata length.
        stark_felt!(2)             // Calldata: num.
    ];
    tx = invoke_tx(execute_calldata, deployed_account_address, max_fee);
    account_tx =
        AccountTransaction::Invoke(InvokeTransaction { nonce: Nonce(stark_felt!(3)), ..tx });
    _actual_execution_info = account_tx.execute(state, block_context).unwrap();
}
