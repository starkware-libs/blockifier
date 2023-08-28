use std::collections::HashMap;

use cairo_vm::vm::runners::cairo_runner::ResourceTracker;
use rstest::{fixture, rstest};
use starknet_api::core::{
    calculate_contract_address, ClassHash, ContractAddress, Nonce, PatriciaKey,
};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransactionV0V1, DeclareTransactionV2, Fee,
    TransactionHash,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};
use starknet_crypto::FieldElement;

use crate::abi::abi_utils::{get_storage_var_address, selector_from_name};
use crate::block_context::BlockContext;
use crate::execution::contract_class::{ContractClass, ContractClassV0, ContractClassV1};
use crate::execution::entry_point::EntryPointExecutionContext;
use crate::state::cached_state::CachedState;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::{
    declare_tx, deploy_account_tx, DictStateReader, NonceManager, ACCOUNT_CONTRACT_CAIRO0_PATH,
    BALANCE, ERC20_CONTRACT_PATH, MAX_FEE, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH,
    TEST_CONTRACT_ADDRESS, TEST_CONTRACT_CAIRO0_PATH, TEST_ERC20_CONTRACT_CLASS_HASH,
    TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::objects::TransactionExecutionInfo;
use crate::transaction::test_utils::{
    account_invoke_tx, create_account_tx_for_validate_test,
    create_state_with_falliable_validation_account, run_invoke_tx, INVALID,
};
use crate::transaction::transaction_types::TransactionType;
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
    let test_account_class_hash = class_hash!(TEST_ACCOUNT_CONTRACT_CLASS_HASH);
    let test_erc20_class_hash = class_hash!(TEST_ERC20_CONTRACT_CLASS_HASH);
    let class_hash_to_class = HashMap::from([
        (test_account_class_hash, ContractClassV0::from_file(ACCOUNT_CONTRACT_CAIRO0_PATH).into()),
        (test_erc20_class_hash, ContractClassV0::from_file(ERC20_CONTRACT_PATH).into()),
    ]);
    // Deploy the erc20 contract.
    // TODO(Dori, 1/9/2023): NEW_TOKEN_SUPPORT consider deploying and using an extra token.
    let test_erc20_address = block_context.deprecated_fee_token_address;
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
    // TODO(Dori, 1/9/2023): NEW_TOKEN_SUPPORT this token should depend on the versions of txs
    //   used to init.
    let fee_token_address = block_context.deprecated_fee_token_address;

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
    state.set_storage_at(fee_token_address, deployed_account_balance_key, stark_felt!(BALANCE));

    let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);
    account_tx.execute(&mut state, &block_context, true, true).unwrap();

    // Declare a contract.
    let contract_class = ContractClassV0::from_file(TEST_CONTRACT_CAIRO0_PATH).into();
    let declare_tx = declare_tx(TEST_CLASS_HASH, account_address, max_fee, None);
    let account_tx = AccountTransaction::Declare(
        DeclareTransaction::new(
            starknet_api::transaction::DeclareTransaction::V1(DeclareTransactionV0V1 {
                nonce: nonce_manager.next(account_address),
                ..declare_tx
            }),
            TransactionHash::default(),
            contract_class,
        )
        .unwrap(),
    );
    account_tx.execute(&mut state, &block_context, true, true).unwrap();

    // Deploy a contract using syscall deploy.
    let entry_point_selector = selector_from_name("deploy_contract");
    let salt = ContractAddressSalt::default();
    let class_hash = class_hash!(TEST_CLASS_HASH);
    run_invoke_tx(
        calldata![
            *account_address.0.key(), // Contract address.
            entry_point_selector.0,   // EP selector.
            stark_felt!(5_u8),        // Calldata length.
            class_hash.0,             // Calldata: class_hash.
            salt.0,                   // Contract_address_salt.
            stark_felt!(2_u8),        // Constructor calldata length.
            stark_felt!(1_u8),        // Constructor calldata: address.
            stark_felt!(1_u8)         // Constructor calldata: value.
        ],
        &mut state,
        account_address,
        &block_context,
        &mut nonce_manager,
        max_fee,
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

#[rstest]
fn test_fee_enforcement(
    block_context: BlockContext,
    #[from(create_state)] mut state: CachedState<DictStateReader>,
) {
    for max_fee_value in 0..2 {
        let max_fee = Fee(max_fee_value);

        let deploy_account_tx = deploy_account_tx(
            TEST_ACCOUNT_CONTRACT_CLASS_HASH,
            max_fee,
            None,
            None,
            &mut NonceManager::default(),
        );

        let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);
        let enforce_fee = account_tx.enforce_fee();
        let result = account_tx.execute(&mut state, &block_context, true, true);
        assert_eq!(result.is_err(), enforce_fee);
    }
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
    run_invoke_tx(
        calldata![
            *contract_address.0.key(), // Contract address.
            entry_point_selector.0,    // EP selector.
            stark_felt!(1_u8),         // Calldata length.
            stark_felt!(2_u8)          // Calldata: num.
        ],
        &mut state,
        account_address,
        &block_context,
        &mut nonce_manager,
        max_fee,
    )
    .unwrap();
}

#[rstest]
// Try two runs for each recursion type: one short run (success), and one that reverts due to step
// limit.
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
    block_context.invoke_tx_max_n_steps = 4000;

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

    let tx_execution_info = run_invoke_tx(
        execute_calldata,
        &mut state,
        account_address,
        &block_context,
        &mut nonce_manager,
        max_fee,
    )
    .unwrap();
    if success {
        assert!(tx_execution_info.revert_error.is_none());
    } else {
        assert!(
            tx_execution_info
                .revert_error
                .unwrap()
                .contains("RunResources has no remaining steps.")
        );
    }
}

#[rstest]
/// Tests that an account invoke transaction that fails the execution phase, still incurs a nonce
/// increase and a fee deduction.
fn test_revert_invoke(
    block_context: BlockContext,
    max_fee: Fee,
    #[from(create_state)] mut state: CachedState<DictStateReader>,
) {
    let mut nonce_manager = NonceManager::default();
    // TODO(Dori, 1/9/2023): NEW_TOKEN_SUPPORT this token should depend on the tx version.
    let fee_token_address = block_context.deprecated_fee_token_address;
    // Deploy an account contract.
    let deploy_account_tx = deploy_account_tx(
        TEST_ACCOUNT_CONTRACT_CLASS_HASH,
        max_fee,
        None,
        None,
        &mut nonce_manager,
    );
    let deployed_account_address = deploy_account_tx.contract_address;

    // Update the balance of the about-to-be deployed account contract in the erc20 contract, so it
    // can pay for the transaction execution.
    let deployed_account_balance_key =
        get_storage_var_address("ERC20_balances", &[*deployed_account_address.0.key()]).unwrap();
    state.set_storage_at(fee_token_address, deployed_account_balance_key, stark_felt!(BALANCE));

    let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);
    let deploy_execution_info = account_tx.execute(&mut state, &block_context, true, true).unwrap();

    // Invoke a function from the newly deployed contract, that changes the state.
    let storage_key = stark_felt!(9_u8);
    let entry_point_selector = selector_from_name("write_and_revert");
    let tx_execution_info = run_invoke_tx(
        calldata![
            *deployed_account_address.0.key(), // Contract address.
            entry_point_selector.0,            // EP selector.
            stark_felt!(2_u8),                 // Calldata length.
            storage_key,
            stark_felt!(99_u8) // Dummy, non-zero value.
        ],
        &mut state,
        deployed_account_address,
        &block_context,
        &mut nonce_manager,
        max_fee,
    )
    .unwrap();

    // TODO(Dori, 1/7/2023): Verify that the actual fee collected is exactly the fee computed for
    // the validate and fee transfer calls.

    // Check that the transaction was reverted.
    assert!(tx_execution_info.revert_error.is_some());

    // Check that the nonce was increased and the fee was deducted.
    let total_deducted_fee = deploy_execution_info.actual_fee.0 + tx_execution_info.actual_fee.0;
    assert_eq!(
        state.get_fee_token_balance(&block_context, &deployed_account_address).unwrap(),
        (stark_felt!(BALANCE - total_deducted_fee), stark_felt!(0_u8))
    );
    assert_eq!(
        state.get_nonce_at(deployed_account_address).unwrap(),
        nonce_manager.next(deployed_account_address)
    );

    // Check that execution state changes were reverted.
    assert_eq!(
        stark_felt!(0_u8),
        state
            .get_storage_at(
                contract_address!(TEST_CONTRACT_ADDRESS),
                StorageKey::try_from(storage_key).unwrap(),
            )
            .unwrap()
    );
}

#[rstest]
/// Tests that failing account deployment should not change state (no fee charge or nonce bump).
fn test_fail_deploy_account(block_context: BlockContext) {
    let mut state = create_state_with_falliable_validation_account();

    let deployed_account_address =
        ContractAddress::try_from(stark_felt!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS)).unwrap();
    let initial_balance =
        state.get_fee_token_balance(&block_context, &deployed_account_address).unwrap();

    // Create and execute (failing) deploy account transaction.
    let deploy_account_tx = create_account_tx_for_validate_test(
        TransactionType::DeployAccount,
        INVALID,
        None,
        &mut NonceManager::default(),
    );
    let deploy_address = deploy_account_tx.get_address_of_deploy().unwrap();
    deploy_account_tx.execute(&mut state, &block_context, true, true).unwrap_err();

    // Assert nonce and balance are unchanged, and that no contract was deployed at the address.
    assert_eq!(state.get_nonce_at(deployed_account_address).unwrap(), Nonce(stark_felt!(0_u8)));
    assert_eq!(
        state.get_fee_token_balance(&block_context, &deployed_account_address).unwrap(),
        initial_balance
    );
    assert_eq!(state.get_class_hash_at(deploy_address).unwrap(), ClassHash::default());
}

#[rstest]
/// Tests that a failing declare transaction should not change state (no fee charge or nonce bump).
fn test_fail_declare(max_fee: Fee, #[from(create_test_init_data)] init_data: TestInitData) {
    let TestInitData { mut state, account_address, mut nonce_manager, block_context, .. } =
        init_data;
    let class_hash = class_hash!(0xdeadeadeaf72_u128);
    let contract_class = ContractClass::V1(ContractClassV1::default());
    let initial_balance = state.get_fee_token_balance(&block_context, &account_address).unwrap();
    let next_nonce = nonce_manager.next(account_address);

    // Cannot fail executing a declare tx unless it's V2 or above, and already declared.
    let declare_tx = DeclareTransactionV2 {
        max_fee,
        class_hash,
        sender_address: account_address,
        ..Default::default()
    };
    state.set_contract_class(&class_hash, contract_class.clone()).unwrap();
    state.set_compiled_class_hash(class_hash, declare_tx.compiled_class_hash).unwrap();
    let declare_account_tx = AccountTransaction::Declare(
        DeclareTransaction::new(
            starknet_api::transaction::DeclareTransaction::V2(DeclareTransactionV2 {
                nonce: next_nonce,
                ..declare_tx
            }),
            TransactionHash::default(),
            contract_class,
        )
        .unwrap(),
    );

    // Fail execution, assert nonce and balance are unchanged.
    declare_account_tx.execute(&mut state, &block_context, true, true).unwrap_err();
    assert_eq!(state.get_nonce_at(account_address).unwrap(), next_nonce);
    assert_eq!(
        state.get_fee_token_balance(&block_context, &account_address).unwrap(),
        initial_balance
    );
}

#[allow(clippy::too_many_arguments)]
fn run_recursive_function(
    state: &mut CachedState<DictStateReader>,
    block_context: &BlockContext,
    max_fee: Fee,
    contract_address: &ContractAddress,
    account_address: &ContractAddress,
    nonce_manager: &mut NonceManager,
    function_name: &str,
    depth: u32,
) -> TransactionExecutionInfo {
    run_invoke_tx(
        calldata![
            *contract_address.0.key(),           // Contract address.
            selector_from_name(function_name).0, // EP selector.
            stark_felt!(1_u8),                   // Calldata length.
            stark_felt!(depth)                   // Calldata: recursion depth.
        ],
        state,
        *account_address,
        block_context,
        nonce_manager,
        max_fee,
    )
    .unwrap()
}

#[rstest]
/// Tests that reverted transactions are charged more fee and steps than their (recursive) prefix
/// successful counterparts.
/// In this test reverted transactions are valid function calls that got insufficient steps limit.
fn test_reverted_reach_steps_limit(
    max_fee: Fee,
    mut block_context: BlockContext,
    #[from(create_state)] state: CachedState<DictStateReader>,
) {
    // Limit the number of execution steps (so we quickly hit the limit).
    block_context.invoke_tx_max_n_steps = 5000;

    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(max_fee, block_context, state);

    // Invoke the `recurse` function with 0 iterations. This call should succeed.
    let result: TransactionExecutionInfo = run_recursive_function(
        &mut state,
        &block_context,
        max_fee,
        &contract_address,
        &account_address,
        &mut nonce_manager,
        "recurse",
        0,
    );
    let n_steps_0 = result.actual_resources.0.get("n_steps").unwrap();
    let actual_fee_0 = result.actual_fee.0;
    // Ensure the transaction was not reverted.
    assert!(!result.is_reverted());

    // Invoke the `recurse` function with 1 iteration. This call should succeed.
    let result: TransactionExecutionInfo = run_recursive_function(
        &mut state,
        &block_context,
        max_fee,
        &contract_address,
        &account_address,
        &mut nonce_manager,
        "recurse",
        1,
    );
    let n_steps_1 = result.actual_resources.0.get("n_steps").unwrap();
    let actual_fee_1 = result.actual_fee.0;
    // Ensure the transaction was not reverted.
    assert!(!result.is_reverted());

    // Make sure that the n_steps and actual_fee are higher as the recursion depth increases.
    assert!(n_steps_1 > n_steps_0);
    assert!(actual_fee_1 > actual_fee_0);

    // Calculate a recursion depth where the transaction will surely fail (not a minimal depth, as
    // base costs are neglected here).
    let steps_diff = n_steps_1 - n_steps_0;
    let fail_depth = block_context.invoke_tx_max_n_steps / (steps_diff as u32);

    // Invoke the `recurse` function with `fail_depth` iterations. This call should fail.
    let result: TransactionExecutionInfo = run_recursive_function(
        &mut state,
        &block_context,
        max_fee,
        &contract_address,
        &account_address,
        &mut nonce_manager,
        "recurse",
        fail_depth,
    );
    let n_steps_fail = result.actual_resources.0.get("n_steps").unwrap();
    let actual_fee_fail: u128 = result.actual_fee.0;
    // Ensure the transaction was reverted.
    assert!(result.is_reverted());

    // Make sure that the failed transaction gets charged for the extra steps taken, compared with
    // the smaller valid transaction.
    assert!(n_steps_fail > n_steps_1);
    assert!(actual_fee_fail > actual_fee_1);

    // Invoke the `recurse` function with `fail_depth`+1 iterations. This call should fail.
    let result: TransactionExecutionInfo = run_recursive_function(
        &mut state,
        &block_context,
        max_fee,
        &contract_address,
        &account_address,
        &mut nonce_manager,
        "recurse",
        fail_depth + 1,
    );
    let n_steps_fail_next = result.actual_resources.0.get("n_steps").unwrap();
    let actual_fee_fail_next: u128 = result.actual_fee.0;
    // Ensure the transaction was reverted.
    assert!(result.is_reverted());

    // Test that the two reverted transactions behave the same.
    assert!(n_steps_fail == n_steps_fail_next);
    assert!(actual_fee_fail == actual_fee_fail_next);
}

#[rstest]
/// Tests that n_steps and actual_fees of reverted transactions invocations are consistent.
/// In this test reverted transactions are recursive function invocations where the innermost call
/// asserts false. We test deltas between consecutive depths, and further depths.
fn test_n_reverted_steps(
    max_fee: Fee,
    block_context: BlockContext,
    #[from(create_state)] state: CachedState<DictStateReader>,
) {
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(max_fee, block_context, state);

    // Invoke the `recursive_fail` function with 0 iterations. This call should fail.
    let result: TransactionExecutionInfo = run_recursive_function(
        &mut state,
        &block_context,
        max_fee,
        &contract_address,
        &account_address,
        &mut nonce_manager,
        "recursive_fail",
        0,
    );
    let n_steps_0 = result.actual_resources.0.get("n_steps").unwrap();
    let actual_fee_0 = result.actual_fee.0;
    // Ensure the transaction was reverted.
    assert!(result.is_reverted());

    // Invoke the `recursive_fail` function with 1 iterations. This call should fail.
    let result: TransactionExecutionInfo = run_recursive_function(
        &mut state,
        &block_context,
        max_fee,
        &contract_address,
        &account_address,
        &mut nonce_manager,
        "recursive_fail",
        1,
    );
    let n_steps_1 = result.actual_resources.0.get("n_steps").unwrap();
    let actual_fee_1 = result.actual_fee.0;
    // Ensure the transaction was reverted.
    assert!(result.is_reverted());

    // Invoke the `recursive_fail` function with 2 iterations. This call should fail.
    let result: TransactionExecutionInfo = run_recursive_function(
        &mut state,
        &block_context,
        max_fee,
        &contract_address,
        &account_address,
        &mut nonce_manager,
        "recursive_fail",
        2,
    );
    let n_steps_2 = result.actual_resources.0.get("n_steps").unwrap();
    let actual_fee_2 = result.actual_fee.0;
    // Ensure the transaction was reverted.
    assert!(result.is_reverted());

    // Make sure that n_steps and actual_fee diffs are the same for two consecutive reverted calls.
    assert!(n_steps_1 - n_steps_0 == n_steps_2 - n_steps_1);
    assert!(actual_fee_1 - actual_fee_0 == actual_fee_2 - actual_fee_1);

    // Save the delta between two consecutive calls to be tested against a much larger recursion.
    let single_call_steps_delta = n_steps_1 - n_steps_0;
    let single_call_fee_delta = actual_fee_1 - actual_fee_0;
    assert!(single_call_steps_delta > 0);
    assert!(single_call_fee_delta > 0);

    // Invoke the `recursive_fail` function with 100 iterations. This call should fail.
    let result: TransactionExecutionInfo = run_recursive_function(
        &mut state,
        &block_context,
        max_fee,
        &contract_address,
        &account_address,
        &mut nonce_manager,
        "recursive_fail",
        100,
    );
    let n_steps_100 = result.actual_resources.0.get("n_steps").unwrap();
    let actual_fee_100 = result.actual_fee.0;
    // Ensure the transaction was reverted.
    assert!(result.is_reverted());

    // Make sure that n_steps and actual_fee grew as expected.
    assert!(n_steps_100 - n_steps_0 == 100 * single_call_steps_delta);
    assert!(actual_fee_100 - actual_fee_0 == 100 * single_call_fee_delta);
}

#[rstest]
/// Tests that steps are correctly limited based on max_fee.
fn test_max_fee_to_max_steps_conversion(
    block_context: BlockContext,
    #[from(create_state)] state: CachedState<DictStateReader>,
) {
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(Fee(MAX_FEE), block_context, state);
    let actual_fee = 659500000000000;
    let execute_calldata = calldata![
        *contract_address.0.key(),        // Contract address.
        selector_from_name("with_arg").0, // EP selector.
        stark_felt!(1_u8),                // Calldata length.
        stark_felt!(25_u8)                // Calldata: arg.
    ];

    // First invocation of `with_arg` gets the exact pre-calculated actual fee as max_fee.
    let account_tx1 = account_invoke_tx(
        execute_calldata.clone(),
        account_address,
        &mut nonce_manager,
        Fee(actual_fee),
    );
    let execution_context1 = EntryPointExecutionContext::new_invoke(
        &block_context,
        &account_tx1.get_account_transaction_context(),
    );
    let max_steps_limit1 = execution_context1.vm_run_resources.get_n_steps();
    let tx_execution_info1 = account_tx1.execute(&mut state, &block_context, true, true).unwrap();
    let n_steps1 = tx_execution_info1.actual_resources.0.get("n_steps").unwrap();

    // Second invocation of `with_arg` gets twice the pre-calculated actual fee as max_fee.
    let account_tx2 = account_invoke_tx(
        execute_calldata,
        account_address,
        &mut nonce_manager,
        Fee(2 * actual_fee),
    );
    let execution_context2 = EntryPointExecutionContext::new_invoke(
        &block_context,
        &account_tx2.get_account_transaction_context(),
    );
    let max_steps_limit2 = execution_context2.vm_run_resources.get_n_steps();
    let tx_execution_info2 = account_tx2.execute(&mut state, &block_context, true, true).unwrap();
    let n_steps2 = tx_execution_info2.actual_resources.0.get("n_steps").unwrap();

    // Test that steps limit doubles as max_fee doubles, but actual consumed steps and fee remains.
    assert!(max_steps_limit2.unwrap() == 2 * max_steps_limit1.unwrap());
    assert!(tx_execution_info1.actual_fee.0 == tx_execution_info2.actual_fee.0);
    assert!(actual_fee == tx_execution_info2.actual_fee.0);
    assert!(n_steps1 == n_steps2);
}

#[rstest]
/// Tests that transactions with insufficient max_fee are reverted, the correct revert_error is
/// recorded and max_fee is charged.
fn test_insufficient_max_fee_reverts(
    block_context: BlockContext,
    #[from(create_state)] state: CachedState<DictStateReader>,
) {
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(Fee(MAX_FEE), block_context, state);

    // Invoke the `recurse` function with depth 1 and MAX_FEE. This call should succeed.
    let tx_execution_info1: TransactionExecutionInfo = run_recursive_function(
        &mut state,
        &block_context,
        Fee(MAX_FEE),
        &contract_address,
        &account_address,
        &mut nonce_manager,
        "recurse",
        1,
    );
    assert!(!tx_execution_info1.is_reverted());
    let actual_fee_depth1 = tx_execution_info1.actual_fee;

    // Invoke the `recurse` function with depth of 2 and the actual fee of depth 1 as max_fee.
    // This call should fail due to insufficient max fee (steps bound based on max_fee is not so
    // tight as to stop execution between iterations 1 and 2).
    let tx_execution_info2: TransactionExecutionInfo = run_recursive_function(
        &mut state,
        &block_context,
        actual_fee_depth1,
        &contract_address,
        &account_address,
        &mut nonce_manager,
        "recurse",
        2,
    );
    assert!(tx_execution_info2.is_reverted());
    assert!(tx_execution_info2.actual_fee == actual_fee_depth1);
    assert!(tx_execution_info2.revert_error.unwrap().starts_with("Insufficient max fee"));

    // Invoke the `recurse` function with depth of 800 and the actual fee of depth 1 as max_fee.
    // This call should fail due to no remaining steps (execution steps based on max_fee are bounded
    // well enough to catch this mid-execution).
    let tx_execution_info3: TransactionExecutionInfo = run_recursive_function(
        &mut state,
        &block_context,
        actual_fee_depth1,
        &contract_address,
        &account_address,
        &mut nonce_manager,
        "recurse",
        800,
    );
    assert!(tx_execution_info3.is_reverted());
    assert!(tx_execution_info3.actual_fee == actual_fee_depth1);
    assert!(
        tx_execution_info3.revert_error.unwrap().contains("RunResources has no remaining steps.")
    );
}

#[allow(clippy::too_many_arguments)]
/// Calls `test_write_and_transfer` with the given parameters.
fn write_and_transfer(
    storage_address: StarkFelt,
    storage_value: StarkFelt,
    recipient: StarkFelt,
    transfer_amount: StarkFelt,
    account_address: ContractAddress,
    test_contract_address: ContractAddress,
    block_context: &BlockContext,
    nonce_manager: &mut NonceManager,
    max_fee: Fee,
    state: &mut CachedState<DictStateReader>,
) -> TransactionExecutionInfo {
    // TODO(Dori, 1/9/2023): NEW_TOKEN_SUPPORT this token should depend on the tx version.
    let fee_token_address = *block_context.deprecated_fee_token_address.0.key();
    let execute_calldata = calldata![
        *test_contract_address.0.key(),                  // Contract address.
        selector_from_name("test_write_and_transfer").0, // EP selector.
        stark_felt!(5_u8),                               // Calldata length.
        storage_address,                                 // Calldata: storage address.
        storage_value,                                   // Calldata: storage value.
        recipient,                                       // Calldata: to.
        transfer_amount,                                 // Calldata: amount.
        fee_token_address                                // Calldata: fee token address.
    ];
    let account_tx = account_invoke_tx(execute_calldata, account_address, nonce_manager, max_fee);
    account_tx.execute(state, block_context, true, true).unwrap()
}

/// Tests that when a transaction drains an account's balance before fee transfer, the execution is
/// reverted.
#[rstest]
fn test_revert_on_overdraft(
    max_fee: Fee,
    block_context: BlockContext,
    #[from(create_state)] state: CachedState<DictStateReader>,
) {
    // TODO(Dori, 1/9/2023): NEW_TOKEN_SUPPORT this token should depend on the tx version.
    let fee_token_address = *block_context.deprecated_fee_token_address.0.key();
    // An address to be written into to observe state changes.
    let storage_address = stark_felt!(10_u8);
    let storage_key = StorageKey::try_from(storage_address).unwrap();
    // Final storage value expected in the address at the end of this test.
    let expected_final_value = stark_felt!(77_u8);
    // An address to be used as recipient of a transfer.
    let recipient = stark_felt!(7_u8);
    let recipient_address = ContractAddress(patricia_key!(recipient));
    // Amount expected to be transferred successfully.
    let final_received_amount = stark_felt!(80_u8);

    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(max_fee, block_context, state);

    // Verify the contract's storage key initial value is empty.
    assert_eq!(state.get_storage_at(contract_address, storage_key).unwrap(), stark_felt!(0_u8));

    // Approve the test contract to transfer funds.
    let approve_calldata = calldata![
        fee_token_address,               // Contract address.
        selector_from_name("approve").0, // EP selector.
        stark_felt!(3_u8),               // Calldata length.
        *contract_address.0.key(),       // Calldata: to.
        stark_felt!(BALANCE),
        stark_felt!(0_u8)
    ];

    let approve_tx: AccountTransaction =
        account_invoke_tx(approve_calldata, account_address, &mut nonce_manager, max_fee);
    let approval_execution_info =
        approve_tx.execute(&mut state, &block_context, true, true).unwrap();
    assert!(!approval_execution_info.is_reverted());

    // Transfer a valid amount of funds to compute the cost of a successful
    // `test_write_and_transfer` operation. This operation should succeed.
    let execution_info = write_and_transfer(
        storage_address,
        expected_final_value,
        recipient,
        final_received_amount,
        account_address,
        contract_address,
        &block_context,
        &mut nonce_manager,
        max_fee,
        &mut state,
    );
    assert!(!execution_info.is_reverted());
    let transfer_tx_fee = execution_info.actual_fee;

    // Check the current balance, before next transaction.
    let (balance, _) = state.get_fee_token_balance(&block_context, &account_address).unwrap();

    // Attempt to transfer the entire balance, such that no funds remain to pay transaction fee.
    // This operation should revert.
    let execution_info = write_and_transfer(
        storage_address,
        stark_felt!(0_u8), // erase current storage value.
        recipient,         // same recipient as before.
        balance,           // transfer the entire balance.
        account_address,
        contract_address,
        &block_context,
        &mut nonce_manager,
        max_fee,
        &mut state,
    );

    // Compute the expected balance after the reverted write+transfer (tx fee should be charged).
    let expected_new_balance: StarkFelt =
        StarkFelt::from(FieldElement::from(balance) - FieldElement::from(transfer_tx_fee.0));

    // Verify the execution was reverted (including nonce bump) with the correct error.
    assert!(execution_info.is_reverted());
    assert!(execution_info.revert_error.unwrap().starts_with("Insufficient fee token balance"));
    assert_eq!(state.get_nonce_at(account_address).unwrap(), nonce_manager.next(account_address));

    // Verify the storage key/value were not updated in the last tx.
    assert_eq!(state.get_storage_at(contract_address, storage_key).unwrap(), expected_final_value);

    // Verify balances of both sender and recipient are as expected.
    assert_eq!(
        state.get_fee_token_balance(&block_context, &account_address).unwrap(),
        (expected_new_balance, stark_felt!(0_u8))
    );
    assert_eq!(
        state.get_fee_token_balance(&block_context, &recipient_address).unwrap(),
        (final_received_amount, stark_felt!(0_u8))
    );
}
