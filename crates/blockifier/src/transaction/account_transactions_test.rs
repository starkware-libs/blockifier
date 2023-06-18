use std::collections::HashMap;

use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransactionV0V1, Fee, InvokeTransaction,
    InvokeTransactionV1,
};
use starknet_api::{calldata, stark_felt};

use crate::abi::abi_utils::{get_storage_var_address, selector_from_name};
use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClassV0;
use crate::state::cached_state::CachedState;
use crate::state::state_api::State;
use crate::test_utils::{
    declare_tx, deploy_account_tx, invoke_tx, DictStateReader, NonceManager, ACCOUNT_CONTRACT_PATH,
    BALANCE, ERC20_CONTRACT_PATH, MAX_FEE, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH,
    TEST_CONTRACT_PATH, TEST_ERC20_CONTRACT_CLASS_HASH,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::transactions::{DeclareTransaction, ExecutableTransaction};

struct TestInitData {
    pub state: CachedState<DictStateReader>,
    pub account_address: ContractAddress,
    pub contract_address: ContractAddress,
    pub nonce_manager: NonceManager,
}

fn create_state() -> CachedState<DictStateReader> {
    let block_context = BlockContext::create_for_account_testing();

    // Declare all the needed contracts.
    let test_account_class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let test_erc20_class_hash = ClassHash(stark_felt!(TEST_ERC20_CONTRACT_CLASS_HASH));
    let class_hash_to_class = HashMap::from([
        (test_account_class_hash, ContractClassV0::from_file(ACCOUNT_CONTRACT_PATH).into()),
        (test_erc20_class_hash, ContractClassV0::from_file(ERC20_CONTRACT_PATH).into()),
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

fn create_test_state(max_fee: Fee, block_context: &BlockContext) -> TestInitData {
    let mut state = create_state();
    let mut nonce_manager = NonceManager::default();

    // Deploy an account contract.
    let deploy_account_tx = deploy_account_tx(
        TEST_ACCOUNT_CONTRACT_CLASS_HASH,
        max_fee,
        None,
        None,
        &mut nonce_manager,
    );
    let account_address = deploy_account_tx.contract_address;

    // Update the balance of the about-to-be deployed account contract in the erc20 contract, so it
    // can pay for the transaction execution.
    let deployed_account_balance_key =
        get_storage_var_address("ERC20_balances", &[*account_address.0.key()]).unwrap();
    state.set_storage_at(
        block_context.fee_token_address,
        deployed_account_balance_key,
        stark_felt!(BALANCE),
    );

    let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);
    account_tx.execute(&mut state, block_context).unwrap();

    // Declare a contract.
    let contract_class = ContractClassV0::from_file(TEST_CONTRACT_PATH).into();
    let declare_tx = declare_tx(TEST_CLASS_HASH, account_address, max_fee, None);
    let account_tx = AccountTransaction::Declare(
        DeclareTransaction::new(
            starknet_api::transaction::DeclareTransaction::V1(DeclareTransactionV0V1 {
                nonce: nonce_manager.next(account_address),
                ..declare_tx
            }),
            contract_class,
        )
        .unwrap(),
    );
    account_tx.execute(&mut state, block_context).unwrap();

    // Deploy a contract using syscall deploy.
    let entry_point_selector = selector_from_name("deploy_contract");
    let salt = ContractAddressSalt::default();
    let class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    let execute_calldata = calldata![
        *account_address.0.key(), // Contract address.
        entry_point_selector.0,   // EP selector.
        stark_felt!(5_u8),        // Calldata length.
        class_hash.0,             // Calldata: class_hash.
        salt.0,                   // Contract_address_salt.
        stark_felt!(2_u8),        // Constructor calldata length.
        stark_felt!(1_u8),        // Constructor calldata: address.
        stark_felt!(1_u8)         // Constructor calldata: value.
    ];
    let tx = invoke_tx(execute_calldata, account_address, max_fee, None);
    let account_tx = AccountTransaction::Invoke(InvokeTransaction::V1(InvokeTransactionV1 {
        nonce: nonce_manager.next(account_address),
        ..tx
    }));
    account_tx.execute(&mut state, block_context).unwrap();

    // Calculate the newly deployed contract address
    let contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &calldata![stark_felt!(1_u8), stark_felt!(1_u8)],
        account_address,
    )
    .unwrap();

    TestInitData { state, account_address, contract_address, nonce_manager }
}

#[test]
fn test_account_flow_test() {
    let max_fee = Fee(MAX_FEE);
    let block_context = &BlockContext::create_for_account_testing();
    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        create_test_state(max_fee, block_context);

    // Invoke a function from the newly deployed contract.
    let entry_point_selector = selector_from_name("return_result");
    let execute_calldata = calldata![
        *contract_address.0.key(), // Contract address.
        entry_point_selector.0,    // EP selector.
        stark_felt!(1_u8),         // Calldata length.
        stark_felt!(2_u8)          // Calldata: num.
    ];
    let tx = invoke_tx(execute_calldata, account_address, max_fee, None);
    let account_tx = AccountTransaction::Invoke(InvokeTransaction::V1(InvokeTransactionV1 {
        nonce: nonce_manager.next(account_address),
        ..tx
    }));
    account_tx.execute(&mut state, block_context).unwrap();
}
