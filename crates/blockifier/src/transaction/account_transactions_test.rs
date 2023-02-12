use std::collections::HashMap;

use starknet_api::core::{calculate_contract_address, ClassHash, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransaction, DeclareTransactionV0V1, Fee,
    InvokeTransactionV1,
};
use starknet_api::{calldata, stark_felt};

use crate::abi::abi_utils::{get_storage_var_address, selector_from_name};
use crate::block_context::BlockContext;
use crate::state::cached_state::CachedState;
use crate::state::state_api::State;
use crate::test_utils::{
    declare_tx, deploy_account_tx, get_contract_class, invoke_tx, DictStateReader,
    ACCOUNT_CONTRACT_PATH, ERC20_CONTRACT_PATH, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH,
    TEST_CONTRACT_PATH, TEST_ERC20_CONTRACT_CLASS_HASH,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::transactions::ExecutableTransaction;

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
    // Deploy the erc20 contract.
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
    let deploy_account_tx =
        deploy_account_tx(TEST_ACCOUNT_CONTRACT_CLASS_HASH, max_fee, None, None);
    let deployed_account_address = deploy_account_tx.contract_address;

    // Update the balance of the about-to-be deployed account contract in the erc20 contract, so it
    // can pay for the transaction execution.
    let deployed_account_balance_key =
        get_storage_var_address("ERC20_balances", &[*deployed_account_address.0.key()]).unwrap();
    state.set_storage_at(
        block_context.fee_token_address,
        deployed_account_balance_key,
        stark_felt!(Fee(BALANCE as u128).0 as u64),
    );

    let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);
    account_tx.execute(state, block_context).unwrap();

    // Declare a contract.
    let contract_class = get_contract_class(TEST_CONTRACT_PATH);
    let declare_tx = declare_tx(TEST_CLASS_HASH, deployed_account_address, max_fee, None);
    let account_tx = AccountTransaction::Declare(
        DeclareTransaction::V1(DeclareTransactionV0V1 {
            nonce: Nonce(stark_felt!(1)),
            ..declare_tx
        }),
        contract_class,
    );
    account_tx.execute(state, block_context).unwrap();

    // Deploy a contract using syscall deploy.
    let entry_point_selector = selector_from_name("deploy_contract");
    let salt = ContractAddressSalt::default();
    let class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    let execute_calldata = calldata![
        *deployed_account_address.0.key(), // Contract address.
        entry_point_selector.0,            // EP selector.
        stark_felt!(5),                    // Calldata length.
        class_hash.0,                      // Calldata: class_hash.
        salt.0,                            // Contract_address_salt.
        stark_felt!(2),                    // Constructor calldata length.
        stark_felt!(1),                    // Constructor calldata: address.
        stark_felt!(1)                     // Constructor calldata: value.
    ];
    let tx = invoke_tx(execute_calldata, deployed_account_address, max_fee, None);
    let account_tx =
        AccountTransaction::Invoke(InvokeTransactionV1 { nonce: Nonce(stark_felt!(2)), ..tx });
    account_tx.execute(state, block_context).unwrap();

    // Calculate the newly deployed contract address
    let contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &calldata![stark_felt!(1), stark_felt!(1)],
        deployed_account_address,
    )
    .unwrap();

    // Invoke a function from the newly deployed contract.
    let entry_point_selector = selector_from_name("return_result");
    let execute_calldata = calldata![
        *contract_address.0.key(), // Contract address.
        entry_point_selector.0,    // EP selector.
        stark_felt!(1),            // Calldata length.
        stark_felt!(2)             // Calldata: num.
    ];
    let tx = invoke_tx(execute_calldata, deployed_account_address, max_fee, None);
    let account_tx =
        AccountTransaction::Invoke(InvokeTransactionV1 { nonce: Nonce(stark_felt!(3)), ..tx });
    account_tx.execute(state, block_context).unwrap();
}
