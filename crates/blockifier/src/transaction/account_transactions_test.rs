use std::collections::HashMap;

use rstest::{fixture, rstest};
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
    pub block_context: BlockContext,
}

#[fixture]
fn max_fee() -> Fee {
    Fee(MAX_FEE)
}

#[fixture]
fn block_context() -> BlockContext {
    BlockContext::create_for_account_testing()
}

#[fixture]
fn create_state(block_context: BlockContext) -> CachedState<DictStateReader> {
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

    CachedState::from(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        ..Default::default()
    })
}

#[fixture]
fn create_test_init_data(
    max_fee: Fee,
    block_context: BlockContext,
    #[from(create_state)] mut state: CachedState<DictStateReader>,
) -> TestInitData {
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
    account_tx.execute(&mut state, &block_context).unwrap();

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
    account_tx.execute(&mut state, &block_context).unwrap();

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
    account_tx.execute(&mut state, &block_context).unwrap();

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

#[rstest]
fn test_account_flow_test(max_fee: Fee, #[from(create_test_init_data)] init_data: TestInitData) {
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = init_data;

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
    account_tx.execute(&mut state, &block_context).unwrap();
}

#[rstest]
#[case(true, true)]
#[case(true, false)]
#[case(false, true)]
#[case(false, false)]
fn test_infinite_recursion(
    #[case] success: bool,
    #[case] normal_recurse: bool,
    #[from(create_state)] state: CachedState<DictStateReader>,
    max_fee: Fee,
    mut block_context: BlockContext,
) {
    // Limit the number of execution steps (so we quickly hit the limit).
    block_context.invoke_tx_max_n_steps = 1000;

    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(max_fee, block_context, state);

    // Two types of recursion: one "normal" recursion, and one that uses the `call_contract`
    // syscall.
    let raw_contract_address = *contract_address.0.key();
    let raw_entry_point_selector =
        selector_from_name(if normal_recurse { "recurse" } else { "recursive_syscall" }).0;

    let recursion_depth = if success { 3_u32 } else { 1000_u32 };

    let execute_calldata = if normal_recurse {
        calldata![
            raw_contract_address,
            raw_entry_point_selector,
            stark_felt!(1_u8),
            stark_felt!(recursion_depth)
        ]
    } else {
        calldata![
            raw_contract_address,
            raw_entry_point_selector,
            stark_felt!(3_u8), // Calldata length.
            raw_contract_address,
            raw_entry_point_selector,
            stark_felt!(recursion_depth)
        ]
    };

    // Try two runs for each recursion type: one short run (success), and one that reverts due to
    // step limit.
    let tx = invoke_tx(execute_calldata, account_address, max_fee, None);
    let account_tx = AccountTransaction::Invoke(InvokeTransaction::V1(InvokeTransactionV1 {
        nonce: nonce_manager.next(account_address),
        ..tx
    }));
    let result = account_tx.execute(&mut state, &block_context);
    if success {
        result.unwrap();
    } else {
        assert!(
            format!("{:?}", result.unwrap_err()).contains("RunResources has no remaining steps.")
        );
    }
}
