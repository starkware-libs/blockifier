use assert_matches::assert_matches;
use cairo_vm::vm::runners::cairo_runner::ResourceTracker;
use rstest::{fixture, rstest};
use starknet_api::core::{ClassHash, ContractAddress, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, DeclareTransactionV0V1, DeclareTransactionV2, Fee, ResourceBoundsMapping,
    TransactionHash, TransactionVersion,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};
use starknet_crypto::FieldElement;

use crate::abi::abi_utils::{get_fee_token_var_address, selector_from_name};
use crate::abi::constants as abi_constants;
use crate::block_context::BlockContext;
use crate::execution::contract_class::{ContractClass, ContractClassV0, ContractClassV1};
use crate::execution::entry_point::EntryPointExecutionContext;
use crate::execution::errors::EntryPointExecutionError;
use crate::fee::fee_checks::FeeCheckError;
use crate::fee::fee_utils::{calculate_tx_l1_gas_usage, get_fee_by_l1_gas_usage};
use crate::fee::gas_usage::estimate_minimal_l1_gas;
use crate::invoke_tx_args;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::{
    create_calldata, declare_tx, deploy_account_tx, DeployTxArgs, InvokeTxArgs, NonceManager,
    BALANCE, DEFAULT_STRK_L1_GAS_PRICE, GRINDY_ACCOUNT_CONTRACT_CAIRO0_PATH, MAX_FEE,
    MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CONTRACT_ADDRESS,
    TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS, TEST_GRINDY_ACCOUNT_CONTRACT_CLASS_HASH,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{FeeType, HasRelatedFeeType};
use crate::transaction::test_utils::{
    account_invoke_tx, create_account_tx_for_validate_test, create_state,
    create_state_with_falliable_validation_account, create_test_init_data, deploy_and_fund_account,
    l1_resource_bounds, run_invoke_tx, TestInitData, INVALID,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transactions::{DeclareTransaction, ExecutableTransaction};

#[fixture]
fn max_fee() -> Fee {
    Fee(MAX_FEE)
}

#[fixture]
fn max_resource_bounds() -> ResourceBoundsMapping {
    l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE)
}

#[fixture]
fn block_context() -> BlockContext {
    BlockContext::create_for_account_testing()
}

#[rstest]
fn test_fee_enforcement(
    block_context: BlockContext,
    #[values(TransactionVersion::ONE, TransactionVersion::THREE)] version: TransactionVersion,
    #[values(true, false)] zero_bounds: bool,
) {
    let mut state = create_state(block_context.clone());
    let deploy_account_tx = deploy_account_tx(
        DeployTxArgs {
            class_hash: class_hash!(TEST_ACCOUNT_CONTRACT_CLASS_HASH),
            max_fee: Fee(u128::from(!zero_bounds)),
            resource_bounds: l1_resource_bounds(u64::from(!zero_bounds), DEFAULT_STRK_L1_GAS_PRICE),
            version,
            ..Default::default()
        },
        &mut NonceManager::default(),
    );

    let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);
    let enforce_fee = account_tx.get_account_tx_context().enforce_fee().unwrap();
    let result = account_tx.execute(&mut state, &block_context, true, true);
    assert_eq!(result.is_err(), enforce_fee);
}

#[rstest]
#[case(TransactionVersion::ZERO)]
#[case(TransactionVersion::ONE)]
#[case(TransactionVersion::THREE)]
fn test_enforce_fee_false_works(
    block_context: BlockContext,
    max_fee: Fee,
    #[case] version: TransactionVersion,
) {
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(max_fee, block_context);
    let tx_execution_info = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee: Fee(0),
            resource_bounds: l1_resource_bounds(0, DEFAULT_STRK_L1_GAS_PRICE),
            sender_address: account_address,
            calldata: create_calldata(
                contract_address,
                "return_result",
                &[stark_felt!(2_u8)]  // Calldata: num.
            ),
            version,
            nonce: nonce_manager.next(account_address),
        },
    )
    .unwrap();
    assert!(!tx_execution_info.is_reverted());
    assert_eq!(tx_execution_info.actual_fee, Fee(0));
}

// TODO(Dori, 15/9/2023): Convert version variance to attribute macro.
// TODO(Dori, 10/10/2023): Add V3 case once `get_account_tx_context` is supported for V3.
#[rstest]
fn test_account_flow_test(
    block_context: BlockContext,
    max_fee: Fee,
    #[values(TransactionVersion::ZERO, TransactionVersion::ONE)] tx_version: TransactionVersion,
    #[values(true, false)] only_query: bool,
) {
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(max_fee, block_context);

    // Invoke a function from the newly deployed contract.
    run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee,
            sender_address: account_address,
            calldata: create_calldata(
                contract_address,
                "return_result",
                &[stark_felt!(2_u8)]  // Calldata: num.
            ),
            version: tx_version,
            nonce: nonce_manager.next(account_address),
            only_query,
        },
    )
    .unwrap();
}

#[rstest]
#[case(TransactionVersion::ZERO)]
#[case(TransactionVersion::ONE)]
// TODO(Nimrod, 10/10/2023): Add V3 case once `get_account_tx_context` is supported for V3.
fn test_invoke_tx_from_non_deployed_account(
    block_context: BlockContext,
    max_fee: Fee,
    #[case] tx_version: TransactionVersion,
) {
    let TestInitData {
        mut state,
        account_address,
        contract_address: _,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(max_fee, block_context);
    // Invoke a function from the newly deployed contract.
    let entry_point_selector = selector_from_name("return_result");

    let non_deployed_contract_address = StarkHash::TWO;

    let tx_result = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee,
            sender_address: account_address,
            calldata: calldata![
                non_deployed_contract_address, // Contract address.
                entry_point_selector.0,    // EP selector.
                stark_felt!(1_u8),         // Calldata length.
                stark_felt!(2_u8)          // Calldata: num.
            ],
            version: tx_version,
            nonce: nonce_manager.next(account_address),
        },
    );
    let expected_error = "is not deployed.";
    match tx_result {
        Ok(info) => {
            //  Make sure the error is because the account wasn't deployed.
            assert!(info.revert_error.is_some_and(|err_str| err_str.contains(expected_error)));
        }
        Err(err) => {
            //  Make sure the error is because the account wasn't deployed.
            assert!(matches!(err, TransactionExecutionError::ExecutionError(
                EntryPointExecutionError::VirtualMachineExecutionErrorWithTrace { trace, .. })
                if trace.contains(expected_error)
            ));
            // We expect to get an error only when tx_version is 0, on other versions to revert.
            assert!(matches!(tx_version, TransactionVersion::ZERO));
        }
    }
}

#[rstest]
// Try two runs for each recursion type: one short run (success), and one that reverts due to step
// limit.
fn test_infinite_recursion(
    #[values(true, false)] success: bool,
    #[values(true, false)] normal_recurse: bool,
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
    } = create_test_init_data(max_fee, block_context);

    let recursion_depth = if success { 3_u32 } else { 1000_u32 };

    let execute_calldata = if normal_recurse {
        create_calldata(contract_address, "recurse", &[stark_felt!(recursion_depth)])
    } else {
        create_calldata(
            contract_address,
            "recursive_syscall",
            &[
                *contract_address.0.key(), // Calldata: raw contract address.
                selector_from_name("recursive_syscall").0, // Calldata: raw selector
                stark_felt!(recursion_depth),
            ],
        )
    };

    let tx_execution_info = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee,
            sender_address: account_address,
            calldata: execute_calldata,
            version: TransactionVersion::ONE,
            nonce: nonce_manager.next(account_address),
        },
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

/// Tests that validation fails on insufficient steps if max fee is too low.
#[rstest]
#[case(TransactionVersion::ONE)]
#[case(TransactionVersion::THREE)]
fn test_max_fee_limit_validate(
    max_fee: Fee,
    block_context: BlockContext,
    #[case] version: TransactionVersion,
    max_resource_bounds: ResourceBoundsMapping,
) {
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(Fee(MAX_FEE), block_context);

    // Declare the grindy-validation account.
    let contract_class = ContractClassV0::from_file(GRINDY_ACCOUNT_CONTRACT_CAIRO0_PATH).into();
    let declare_tx =
        declare_tx(TEST_GRINDY_ACCOUNT_CONTRACT_CLASS_HASH, account_address, Fee(MAX_FEE), None);
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

    // Deploy grindy account with a lot of grind in the constructor.
    // Expect this to fail without bumping nonce, so pass a temporary nonce manager.
    let (deploy_account_tx, _) = deploy_and_fund_account(
        &mut state,
        &mut NonceManager::default(),
        &block_context,
        DeployTxArgs {
            class_hash: class_hash!(TEST_GRINDY_ACCOUNT_CONTRACT_CLASS_HASH),
            max_fee,
            constructor_calldata: calldata![stark_felt!(1_u8)], // Grind in deploy phase.
            ..Default::default()
        },
    );
    let error = deploy_account_tx.execute(&mut state, &block_context, true, true).unwrap_err();
    assert_matches!(
        error,
        TransactionExecutionError::ValidateTransactionError(
            EntryPointExecutionError::VirtualMachineExecutionErrorWithTrace { trace, .. }
        )
        if trace.contains("no remaining steps")
    );

    // Deploy grindy account successfully this time.
    let (deploy_account_tx, grindy_account_address) = deploy_and_fund_account(
        &mut state,
        &mut nonce_manager,
        &block_context,
        DeployTxArgs {
            class_hash: class_hash!(TEST_GRINDY_ACCOUNT_CONTRACT_CLASS_HASH),
            max_fee,
            constructor_calldata: calldata![stark_felt!(0_u8)], // Do not grind in deploy phase.
            ..Default::default()
        },
    );
    deploy_account_tx.execute(&mut state, &block_context, true, true).unwrap();

    // Invoke a function that grinds validate (any function will do); set bounds low enough to fail
    // on this grind.
    // To ensure bounds are low enough, estimate minimal resources consumption, and set bounds
    // slightly above them.
    let tx_args = invoke_tx_args! {
        sender_address: grindy_account_address,
        calldata: create_calldata(
            contract_address,
            "return_result",
            &[stark_felt!(2_u8)], // Calldata: num.
        ),
        version,
        nonce: nonce_manager.next(grindy_account_address)
    };

    let account_tx = account_invoke_tx(invoke_tx_args! {
        // Temporary upper bounds; just for gas estimation.
        max_fee: Fee(MAX_FEE),
        resource_bounds: max_resource_bounds,
        ..tx_args.clone()
    });
    let estimated_min_l1_gas = estimate_minimal_l1_gas(&block_context, &account_tx).unwrap();
    let estimated_min_fee =
        get_fee_by_l1_gas_usage(&block_context, estimated_min_l1_gas, &account_tx.fee_type());

    let error = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee: estimated_min_fee,
            resource_bounds: l1_resource_bounds(
                estimated_min_l1_gas as u64,
                block_context.gas_prices.get_by_fee_type(&account_tx.fee_type())
            ),
            ..tx_args
        },
    )
    .unwrap_err();

    assert_matches!(
        error,
        TransactionExecutionError::ValidateTransactionError(
            EntryPointExecutionError::VirtualMachineExecutionErrorWithTrace { trace, .. }
        )
        if trace.contains("no remaining steps")
    );
}

#[rstest]
#[case(TransactionVersion::ONE)]
#[case(TransactionVersion::THREE)]
fn test_recursion_depth_exceeded(
    #[case] tx_version: TransactionVersion,
    block_context: BlockContext,
    max_fee: Fee,
    max_resource_bounds: ResourceBoundsMapping,
) {
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(max_fee, block_context);

    // Positive test

    // Technical details for this specific recursive entry point:
    // The maximum inner recursion depth is reduced by 2 from the global entry point limit for two
    // reasons:
    // 1. An additional call is made initially before entering the recursion.
    // 2. The base case for recursion occurs at depth 0, not at depth 1.
    let max_inner_recursion_depth = (block_context.max_recursion_depth - 2) as u8;

    let recursive_syscall_entry_point_name = "recursive_syscall";
    let calldata = create_calldata(
        contract_address,
        recursive_syscall_entry_point_name,
        &[
            *contract_address.0.key(), // Calldata: raw contract address.
            selector_from_name(recursive_syscall_entry_point_name).0, // Calldata: raw selector.
            stark_felt!(max_inner_recursion_depth),
        ],
    );
    let invoke_args = invoke_tx_args! {
        max_fee,
        sender_address: account_address,
        calldata,
        version: tx_version,
        nonce: nonce_manager.next(account_address),
        resource_bounds: max_resource_bounds,
    };
    let tx_execution_info = run_invoke_tx(&mut state, &block_context, invoke_args.clone());

    assert!(tx_execution_info.unwrap().revert_error.is_none());

    // Negative test

    let exceeding_recursion_depth = max_inner_recursion_depth + 1;

    let calldata = create_calldata(
        contract_address,
        recursive_syscall_entry_point_name,
        &[
            *contract_address.0.key(), // Calldata: raw contract address.
            selector_from_name(recursive_syscall_entry_point_name).0, // Calldata: raw selector.
            stark_felt!(exceeding_recursion_depth),
        ],
    );
    let invoke_args =
        InvokeTxArgs { calldata, nonce: nonce_manager.next(account_address), ..invoke_args };
    let tx_execution_info = run_invoke_tx(&mut state, &block_context, invoke_args);

    assert!(tx_execution_info.unwrap().revert_error.unwrap().contains("recursion depth exceeded"));
}

#[rstest]
/// Tests that an account invoke transaction that fails the execution phase, still incurs a nonce
/// increase and a fee deduction.
fn test_revert_invoke(block_context: BlockContext, max_fee: Fee) {
    let mut state = create_state(block_context.clone());
    let mut nonce_manager = NonceManager::default();
    // TODO(Dori, 1/9/2023): NEW_TOKEN_SUPPORT this token should depend on the tx version.
    let fee_token_address = block_context.fee_token_addresses.eth_fee_token_address;
    // Deploy an account contract.
    let deploy_account_tx = deploy_account_tx(
        DeployTxArgs {
            class_hash: class_hash!(TEST_ACCOUNT_CONTRACT_CLASS_HASH),
            max_fee,
            ..Default::default()
        },
        &mut nonce_manager,
    );
    let deployed_account_address = deploy_account_tx.contract_address;

    // Update the balance of the about-to-be deployed account contract in the erc20 contract, so it
    // can pay for the transaction execution.
    let deployed_account_balance_key = get_fee_token_var_address(&deployed_account_address);
    state.set_storage_at(fee_token_address, deployed_account_balance_key, stark_felt!(BALANCE));

    let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);
    let account_tx_context = account_tx.get_account_tx_context();
    let deploy_execution_info = account_tx.execute(&mut state, &block_context, true, true).unwrap();

    // Invoke a function from the newly deployed contract, that changes the state.
    let storage_key = stark_felt!(9_u8);
    let tx_execution_info = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee,
            sender_address: deployed_account_address,
            calldata: create_calldata(
                deployed_account_address,
                "write_and_revert",
                &[
                    storage_key,
                    stark_felt!(99_u8) // Dummy, non-zero value.
                ]
            ),
            version: TransactionVersion::ONE,
            nonce: nonce_manager.next(deployed_account_address),
        },
    )
    .unwrap();

    // TODO(Dori, 1/7/2023): Verify that the actual fee collected is exactly the fee computed for
    // the validate and fee transfer calls.

    // Check that the transaction was reverted.
    assert!(tx_execution_info.revert_error.is_some());

    // Check that the nonce was increased and the fee was deducted.
    let total_deducted_fee = deploy_execution_info.actual_fee.0 + tx_execution_info.actual_fee.0;
    assert_eq!(
        state
            .get_fee_token_balance(
                &deployed_account_address,
                &block_context.fee_token_address(&account_tx_context.fee_type())
            )
            .unwrap(),
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

    // Create and execute (failing) deploy account transaction.
    let deploy_account_tx = create_account_tx_for_validate_test(
        TransactionType::DeployAccount,
        INVALID,
        None,
        &mut NonceManager::default(),
    );
    let fee_token_address = block_context.fee_token_address(&deploy_account_tx.fee_type());

    let deploy_address = match &deploy_account_tx {
        AccountTransaction::DeployAccount(deploy_tx) => deploy_tx.contract_address,
        _ => unreachable!("deploy_account_tx is a DeployAccount"),
    };

    let initial_balance =
        state.get_fee_token_balance(&deployed_account_address, &fee_token_address).unwrap();
    deploy_account_tx.execute(&mut state, &block_context, true, true).unwrap_err();

    // Assert nonce and balance are unchanged, and that no contract was deployed at the address.
    assert_eq!(state.get_nonce_at(deployed_account_address).unwrap(), Nonce(stark_felt!(0_u8)));
    assert_eq!(
        state.get_fee_token_balance(&deployed_account_address, &fee_token_address).unwrap(),
        initial_balance
    );
    assert_eq!(state.get_class_hash_at(deploy_address).unwrap(), ClassHash::default());
}

#[rstest]
/// Tests that a failing declare transaction should not change state (no fee charge or nonce bump).
fn test_fail_declare(block_context: BlockContext, max_fee: Fee) {
    let TestInitData { mut state, account_address, mut nonce_manager, block_context, .. } =
        create_test_init_data(max_fee, block_context);
    let class_hash = class_hash!(0xdeadeadeaf72_u128);
    let contract_class = ContractClass::V1(ContractClassV1::default());
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
    let account_tx_context = declare_account_tx.get_account_tx_context();
    let initial_balance = state
        .get_fee_token_balance(
            &account_address,
            &block_context.fee_token_address(&account_tx_context.fee_type()),
        )
        .unwrap();
    declare_account_tx.execute(&mut state, &block_context, true, true).unwrap_err();

    assert_eq!(state.get_nonce_at(account_address).unwrap(), next_nonce);
    assert_eq!(
        state
            .get_fee_token_balance(
                &account_address,
                &block_context.fee_token_address(&account_tx_context.fee_type())
            )
            .unwrap(),
        initial_balance
    );
}

fn recursive_function_calldata(
    contract_address: &ContractAddress,
    depth: u32,
    failure_variant: bool,
) -> Calldata {
    create_calldata(
        *contract_address,
        if failure_variant { "recursive_fail" } else { "recurse" },
        &[stark_felt!(depth)], // Calldata: recursion depth.
    )
}

#[rstest]
/// Tests that reverted transactions are charged more fee and steps than their (recursive) prefix
/// successful counterparts.
/// In this test reverted transactions are valid function calls that got insufficient steps limit.
#[case(TransactionVersion::ONE)]
#[case(TransactionVersion::THREE)]
fn test_reverted_reach_steps_limit(
    max_fee: Fee,
    max_resource_bounds: ResourceBoundsMapping,
    block_context: BlockContext,
    #[case] version: TransactionVersion,
) {
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        mut block_context,
    } = create_test_init_data(max_fee, block_context);

    // Limit the number of execution steps (so we quickly hit the limit).
    block_context.invoke_tx_max_n_steps = 5000;
    let recursion_base_args = invoke_tx_args! {
        max_fee,
        resource_bounds: max_resource_bounds,
        sender_address: account_address,
        version,
    };

    // Invoke the `recurse` function with 0 iterations. This call should succeed.
    let result = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            nonce: nonce_manager.next(account_address),
            calldata: recursive_function_calldata(&contract_address, 0, false),
            ..recursion_base_args.clone()
        },
    )
    .unwrap();
    let n_steps_0 = result.actual_resources.n_steps();
    let actual_fee_0 = result.actual_fee.0;
    // Ensure the transaction was not reverted.
    assert!(!result.is_reverted());

    // Invoke the `recurse` function with 1 iteration. This call should succeed.
    let result = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            nonce: nonce_manager.next(account_address),
            calldata: recursive_function_calldata(&contract_address, 1, false),
            ..recursion_base_args.clone()
        },
    )
    .unwrap();
    let n_steps_1 = result.actual_resources.n_steps();
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
    let result = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            nonce: nonce_manager.next(account_address),
            calldata: recursive_function_calldata(&contract_address, fail_depth, false),
            ..recursion_base_args.clone()
        },
    )
    .unwrap();
    let n_steps_fail = result.actual_resources.n_steps();
    let actual_fee_fail: u128 = result.actual_fee.0;
    // Ensure the transaction was reverted.
    assert!(result.is_reverted());

    // Make sure that the failed transaction gets charged for the extra steps taken, compared with
    // the smaller valid transaction.
    assert!(n_steps_fail > n_steps_1);
    assert!(actual_fee_fail > actual_fee_1);

    // Invoke the `recurse` function with `fail_depth`+1 iterations. This call should fail.
    let result = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            nonce: nonce_manager.next(account_address),
            calldata: recursive_function_calldata(&contract_address, fail_depth + 1, false),
            ..recursion_base_args
        },
    )
    .unwrap();
    let n_steps_fail_next = result.actual_resources.n_steps();
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
fn test_n_reverted_steps(max_fee: Fee, block_context: BlockContext) {
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(max_fee, block_context);
    let recursion_base_args = invoke_tx_args! {
        max_fee,
        sender_address: account_address,
        version: TransactionVersion::ONE,
    };

    // Invoke the `recursive_fail` function with 0 iterations. This call should fail.
    let result = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            nonce: nonce_manager.next(account_address),
            calldata: recursive_function_calldata(&contract_address, 0, true),
            ..recursion_base_args.clone()
        },
    )
    .unwrap();
    // Ensure the transaction was reverted.
    assert!(result.is_reverted());
    let mut actual_resources_0 = result.actual_resources.clone();
    let n_steps_0 = result.actual_resources.n_steps();
    let actual_fee_0 = result.actual_fee.0;

    // Invoke the `recursive_fail` function with 1 iterations. This call should fail.
    let result = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            nonce: nonce_manager.next(account_address),
            calldata: recursive_function_calldata(&contract_address, 1, true),
            ..recursion_base_args.clone()
        },
    )
    .unwrap();
    // Ensure the transaction was reverted.
    assert!(result.is_reverted());
    let actual_resources_1 = result.actual_resources;
    let n_steps_1 = actual_resources_1.n_steps();
    let actual_fee_1 = result.actual_fee.0;

    // Invoke the `recursive_fail` function with 2 iterations. This call should fail.
    let result = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            nonce: nonce_manager.next(account_address),
            calldata: recursive_function_calldata(&contract_address, 2, true),
            ..recursion_base_args.clone()
        },
    )
    .unwrap();
    let n_steps_2 = result.actual_resources.n_steps();
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

    // Make sure the resources in block of invocation 0 and 1 are the same, except for the number
    // of cairo steps.
    actual_resources_0
        .0
        .insert(abi_constants::N_STEPS_RESOURCE.to_string(), n_steps_0 + single_call_steps_delta);
    assert_eq!(actual_resources_0, actual_resources_1);
    actual_resources_0.0.insert(abi_constants::N_STEPS_RESOURCE.to_string(), n_steps_0);

    // Invoke the `recursive_fail` function with 100 iterations. This call should fail.
    let result = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            nonce: nonce_manager.next(account_address),
            calldata: recursive_function_calldata(&contract_address, 100, true),
            ..recursion_base_args
        },
    )
    .unwrap();
    let n_steps_100 = result.actual_resources.n_steps();
    let actual_fee_100 = result.actual_fee.0;
    // Ensure the transaction was reverted.
    assert!(result.is_reverted());

    // Make sure that n_steps and actual_fee grew as expected.
    assert!(n_steps_100 - n_steps_0 == 100 * single_call_steps_delta);
    assert!(actual_fee_100 - actual_fee_0 == 100 * single_call_fee_delta);
}

#[rstest]
/// Tests that steps are correctly limited based on max_fee.
#[case(TransactionVersion::ONE)]
#[case(TransactionVersion::THREE)]
fn test_max_fee_to_max_steps_conversion(
    block_context: BlockContext,
    #[case] version: TransactionVersion,
) {
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(Fee(MAX_FEE), block_context);
    let actual_fee = 670900000000000;
    let actual_gas_used = 6709;
    let actual_strk_gas_price = block_context.gas_prices.get_by_fee_type(&FeeType::Strk);
    let execute_calldata = create_calldata(
        contract_address,
        "with_arg",
        &[stark_felt!(25_u8)], // Calldata: arg.
    );

    // First invocation of `with_arg` gets the exact pre-calculated actual fee as max_fee.
    let account_tx1 = account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(actual_fee),
        sender_address: account_address,
        calldata: execute_calldata.clone(),
        version,
        resource_bounds: l1_resource_bounds(actual_gas_used, actual_strk_gas_price),
        nonce: nonce_manager.next(account_address),
    });
    let execution_context1 = EntryPointExecutionContext::new_invoke(
        &block_context,
        &account_tx1.get_account_tx_context(),
        true,
    )
    .unwrap();
    let max_steps_limit1 = execution_context1.vm_run_resources.get_n_steps();
    let tx_execution_info1 = account_tx1.execute(&mut state, &block_context, true, true).unwrap();
    let n_steps1 = tx_execution_info1.actual_resources.n_steps();
    let gas_used1 =
        calculate_tx_l1_gas_usage(&tx_execution_info1.actual_resources, &block_context).unwrap();

    // Second invocation of `with_arg` gets twice the pre-calculated actual fee as max_fee.
    let account_tx2 = account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(2 * actual_fee),
        sender_address: account_address,
        calldata: execute_calldata,
        version,
        resource_bounds: l1_resource_bounds(2 * actual_gas_used, actual_strk_gas_price),
        nonce: nonce_manager.next(account_address),
    });
    let execution_context2 = EntryPointExecutionContext::new_invoke(
        &block_context,
        &account_tx2.get_account_tx_context(),
        true,
    )
    .unwrap();
    let max_steps_limit2 = execution_context2.vm_run_resources.get_n_steps();
    let tx_execution_info2 = account_tx2.execute(&mut state, &block_context, true, true).unwrap();
    let n_steps2 = tx_execution_info2.actual_resources.n_steps();
    let gas_used2 =
        calculate_tx_l1_gas_usage(&tx_execution_info2.actual_resources, &block_context).unwrap();

    // Test that steps limit doubles as max_fee doubles, but actual consumed steps and fee remains.
    assert_eq!(max_steps_limit2.unwrap(), 2 * max_steps_limit1.unwrap());
    assert_eq!(tx_execution_info1.actual_fee.0, tx_execution_info2.actual_fee.0);
    assert_eq!(actual_fee, tx_execution_info2.actual_fee.0);
    assert_eq!(actual_gas_used, gas_used2 as u64);
    assert_eq!(n_steps1, n_steps2);
    assert_eq!(gas_used1, gas_used2);
}

#[rstest]
/// Tests that transactions with insufficient max_fee are reverted, the correct revert_error is
/// recorded and max_fee is charged.
fn test_insufficient_max_fee_reverts(block_context: BlockContext) {
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(Fee(MAX_FEE), block_context);
    let recursion_base_args = invoke_tx_args! {
        sender_address: account_address,
        version: TransactionVersion::ONE,
    };

    // Invoke the `recurse` function with depth 1 and MAX_FEE. This call should succeed.
    let tx_execution_info1 = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee: Fee(MAX_FEE),
            nonce: nonce_manager.next(account_address),
            calldata: recursive_function_calldata(&contract_address, 1, false),
            ..recursion_base_args.clone()
        },
    )
    .unwrap();
    assert!(!tx_execution_info1.is_reverted());
    let actual_fee_depth1 = tx_execution_info1.actual_fee;

    // Invoke the `recurse` function with depth of 2 and the actual fee of depth 1 as max_fee.
    // This call should fail due to insufficient max fee (steps bound based on max_fee is not so
    // tight as to stop execution between iterations 1 and 2).
    let tx_execution_info2 = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee: actual_fee_depth1,
            nonce: nonce_manager.next(account_address),
            calldata: recursive_function_calldata(&contract_address, 2, false),
            ..recursion_base_args.clone()
        },
    )
    .unwrap();
    assert!(tx_execution_info2.is_reverted());
    assert!(tx_execution_info2.actual_fee == actual_fee_depth1);
    assert!(tx_execution_info2.revert_error.unwrap().starts_with("Insufficient max fee"));

    // Invoke the `recurse` function with depth of 800 and the actual fee of depth 1 as max_fee.
    // This call should fail due to no remaining steps (execution steps based on max_fee are bounded
    // well enough to catch this mid-execution).
    let tx_execution_info3 = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee: actual_fee_depth1,
            nonce: nonce_manager.next(account_address),
            calldata: recursive_function_calldata(&contract_address, 800, false),
            ..recursion_base_args
        },
    )
    .unwrap();
    assert!(tx_execution_info3.is_reverted());
    assert!(tx_execution_info3.actual_fee == actual_fee_depth1);
    assert!(
        tx_execution_info3.revert_error.unwrap().contains("RunResources has no remaining steps.")
    );
}

fn calldata_for_write_and_transfer(
    test_contract_address: ContractAddress,
    storage_address: StarkFelt,
    storage_value: StarkFelt,
    recipient: StarkFelt,
    transfer_amount: StarkFelt,
    fee_token_address: ContractAddress,
) -> Calldata {
    create_calldata(
        test_contract_address,
        "test_write_and_transfer",
        &[
            storage_address,            // Calldata: storage address.
            storage_value,              // Calldata: storage value.
            recipient,                  // Calldata: to.
            transfer_amount,            // Calldata: amount.
            *fee_token_address.0.key(), // Calldata: fee token address.
        ],
    )
}

/// Tests that when a transaction drains an account's balance before fee transfer, the execution is
/// reverted.
#[rstest]
#[case(TransactionVersion::ONE, FeeType::Eth)]
#[case(TransactionVersion::THREE, FeeType::Strk)]
fn test_revert_on_overdraft(
    max_fee: Fee,
    max_resource_bounds: ResourceBoundsMapping,
    block_context: BlockContext,
    #[case] version: TransactionVersion,
    #[case] fee_type: FeeType,
) {
    let fee_token_address = block_context.fee_token_addresses.get_by_fee_type(&fee_type);
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
    } = create_test_init_data(max_fee, block_context);

    // Verify the contract's storage key initial value is empty.
    assert_eq!(state.get_storage_at(contract_address, storage_key).unwrap(), stark_felt!(0_u8));

    // Approve the test contract to transfer funds.
    let approve_calldata = create_calldata(
        fee_token_address,
        "approve",
        &[
            *contract_address.0.key(), // Calldata: to.
            stark_felt!(BALANCE),
            stark_felt!(0_u8),
        ],
    );

    let approve_tx: AccountTransaction = account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: account_address,
        calldata: approve_calldata,
        version,
        resource_bounds: max_resource_bounds.clone(),
        nonce: nonce_manager.next(account_address),
    });
    let account_tx_context = approve_tx.get_account_tx_context();
    let approval_execution_info =
        approve_tx.execute(&mut state, &block_context, true, true).unwrap();
    assert!(!approval_execution_info.is_reverted());

    // Transfer a valid amount of funds to compute the cost of a successful
    // `test_write_and_transfer` operation. This operation should succeed.
    let execution_info = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee,
            sender_address: account_address,
            calldata: calldata_for_write_and_transfer(
                contract_address,
                storage_address,
                expected_final_value,
                recipient,
                final_received_amount,
                fee_token_address
            ),
            version,
            resource_bounds: max_resource_bounds.clone(),
            nonce: nonce_manager.next(account_address),
        },
    )
    .unwrap();

    assert!(!execution_info.is_reverted());
    let transfer_tx_fee = execution_info.actual_fee;

    // Check the current balance, before next transaction.
    let (balance, _) = state
        .get_fee_token_balance(
            &account_address,
            &block_context.fee_token_address(&account_tx_context.fee_type()),
        )
        .unwrap();

    // Attempt to transfer the entire balance, such that no funds remain to pay transaction fee.
    // This operation should revert.
    let execution_info = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee,
            sender_address: account_address,
            calldata: calldata_for_write_and_transfer(
                contract_address,
                storage_address,
                stark_felt!(0_u8),
                recipient,
                balance,
                fee_token_address
            ),
            version,
            resource_bounds: max_resource_bounds.clone(),
            nonce: nonce_manager.next(account_address),
        },
    )
    .unwrap();

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
        state
            .get_fee_token_balance(
                &account_address,
                &block_context.fee_token_address(&account_tx_context.fee_type()),
            )
            .unwrap(),
        (expected_new_balance, stark_felt!(0_u8))
    );
    assert_eq!(
        state
            .get_fee_token_balance(
                &recipient_address,
                &block_context.fee_token_address(&account_tx_context.fee_type())
            )
            .unwrap(),
        (final_received_amount, stark_felt!(0_u8))
    );
}

/// Tests that when a transaction requires more resources than what the sender bounds allow, the
/// execution is reverted; in the non-revertible case, checks for the correct error.
#[rstest]
#[case(TransactionVersion::ZERO, "", false)]
#[case(TransactionVersion::ONE, "Insufficient max fee", true)]
#[case(TransactionVersion::THREE, "Insufficient max L1 gas", true)]
fn test_revert_on_resource_overuse(
    max_fee: Fee,
    max_resource_bounds: ResourceBoundsMapping,
    block_context: BlockContext,
    #[case] version: TransactionVersion,
    #[case] expected_error_prefix: &str,
    #[case] is_revertible: bool,
) {
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(max_fee, block_context);

    let n_writes = 5_u8;
    let base_args = invoke_tx_args! { sender_address: account_address, version };

    // Utility function to generate calldata for the `write_a_lot` function.
    // Change the written value each call to keep cost high.
    let mut value_to_write = 1_u8;
    let mut write_a_lot_calldata = || {
        value_to_write += 1;
        create_calldata(
            contract_address,
            "write_a_lot",
            &[stark_felt!(n_writes), stark_felt!(value_to_write)],
        )
    };

    // Run a "heavy" transaction and measure the resources used.
    // In this context, "heavy" means: a substantial fraction of the cost is not cairo steps.
    // We need this kind of invocation, to be able to test the specific scenario: the resource
    // bounds must be enough to allow completion of the transaction, and yet must still fail
    // post-execution bounds check.
    let execution_info_measure = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee,
            resource_bounds: max_resource_bounds.clone(),
            nonce: nonce_manager.next(account_address),
            calldata: write_a_lot_calldata(),
            ..base_args.clone()
        },
    )
    .unwrap();
    assert_eq!(execution_info_measure.revert_error, None);
    let actual_fee = execution_info_measure.actual_fee;
    let actual_gas_usage = calculate_tx_l1_gas_usage(
        &execution_info_measure.actual_resources,
        &block_context,
    )
    .unwrap() as u64;

    // Run the same function, with a different written value (to keep cost high), with the actual
    // resources used as upper bounds. Make sure execution does not revert.
    let execution_info_tight = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee: actual_fee,
            resource_bounds: l1_resource_bounds(actual_gas_usage, MAX_L1_GAS_PRICE),
            nonce: nonce_manager.next(account_address),
            calldata: write_a_lot_calldata(),
            ..base_args.clone()
        },
    )
    .unwrap();
    assert_eq!(execution_info_tight.revert_error, None);
    assert_eq!(execution_info_tight.actual_fee, actual_fee);
    assert_eq!(execution_info_tight.actual_resources, execution_info_measure.actual_resources);

    // Re-run the same function with max bounds slightly below the actual usage, and verify it's
    // reverted.
    let low_max_fee = Fee(execution_info_measure.actual_fee.0 - 1);
    let execution_info_result = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee: low_max_fee,
            resource_bounds: l1_resource_bounds(actual_gas_usage - 1, MAX_L1_GAS_PRICE),
            nonce: nonce_manager.next(account_address),
            calldata: write_a_lot_calldata(),
            ..base_args
        },
    );

    // Assert the transaction was reverted with the correct error.
    if is_revertible {
        assert!(
            execution_info_result.unwrap().revert_error.unwrap().starts_with(expected_error_prefix)
        );
    } else {
        assert_matches!(
            execution_info_result.unwrap_err(),
            TransactionExecutionError::FeeCheckError(
                FeeCheckError::MaxFeeExceeded { max_fee, actual_fee: fee_in_error }
            )
            if (max_fee, fee_in_error) == (low_max_fee, actual_fee)
        );
    }
}
