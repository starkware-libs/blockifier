use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use assert_matches::assert_matches;
use cairo_felt::Felt252;
use cairo_vm::vm::runners::cairo_runner::ResourceTracker;
use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::core::{
    calculate_contract_address, ClassHash, ContractAddress, Nonce, PatriciaKey,
};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransactionV2, Fee, ResourceBoundsMapping,
    TransactionHash, TransactionVersion,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};

use crate::abi::abi_utils::{
    get_fee_token_var_address, get_storage_var_address, selector_from_name,
};
use crate::abi::constants as abi_constants;
use crate::context::BlockContext;
use crate::execution::contract_class::{ContractClass, ContractClassV1};
use crate::execution::entry_point::EntryPointExecutionContext;
use crate::execution::errors::EntryPointExecutionError;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::fee_utils::{calculate_tx_gas_vector, get_fee_by_gas_vector};
use crate::fee::gas_usage::estimate_minimal_gas_vector;
use crate::state::cached_state::{CachedState, StateChangesCount};
use crate::state::state_api::{State, StateReader};
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::declare::declare_tx;
use crate::test_utils::deploy_account::deploy_account_tx;
use crate::test_utils::initial_test_state::{fund_account, test_state};
use crate::test_utils::invoke::InvokeTxArgs;
use crate::test_utils::{
    create_calldata, create_trivial_calldata, CairoVersion, NonceManager, BALANCE,
    DEFAULT_STRK_L1_GAS_PRICE, MAX_FEE, MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants::TRANSFER_ENTRY_POINT_NAME;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{FeeType, HasRelatedFeeType, TransactionInfoCreator};
use crate::transaction::test_utils::{
    account_invoke_tx, block_context, calculate_class_info_for_testing,
    create_account_tx_for_validate_test, create_test_init_data, deploy_and_fund_account,
    l1_resource_bounds, max_fee, max_resource_bounds, run_invoke_tx, FaultyAccountTxCreatorArgs,
    TestInitData, INVALID,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transactions::{DeclareTransaction, ExecutableTransaction};
use crate::{
    check_transaction_execution_error_for_invalid_scenario, declare_tx_args,
    deploy_account_tx_args, invoke_tx_args,
};

#[rstest]
fn test_fee_enforcement(
    block_context: BlockContext,
    #[values(TransactionVersion::ONE, TransactionVersion::THREE)] version: TransactionVersion,
    #[values(true, false)] zero_bounds: bool,
) {
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo0);
    let state = &mut test_state(&block_context.chain_info, BALANCE, &[(account, 1)]);
    let deploy_account_tx = deploy_account_tx(
        deploy_account_tx_args! {
            class_hash: account.get_class_hash(),
            max_fee: Fee(u128::from(!zero_bounds)),
            resource_bounds: l1_resource_bounds(u64::from(!zero_bounds), DEFAULT_STRK_L1_GAS_PRICE),
            version,
        },
        &mut NonceManager::default(),
    );

    let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);
    let enforce_fee = account_tx.create_tx_info().enforce_fee().unwrap();
    let result = account_tx.execute(state, &block_context, true, true);
    assert_eq!(result.is_err(), enforce_fee);
}

#[rstest]
#[case(TransactionVersion::ZERO)]
#[case(TransactionVersion::ONE)]
#[case(TransactionVersion::THREE)]
fn test_enforce_fee_false_works(block_context: BlockContext, #[case] version: TransactionVersion) {
    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        create_test_init_data(&block_context.chain_info, CairoVersion::Cairo0);
    let tx_execution_info = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee: Fee(0),
            resource_bounds: l1_resource_bounds(0, DEFAULT_STRK_L1_GAS_PRICE),
            sender_address: account_address,
            calldata: create_trivial_calldata(contract_address),
            version,
            nonce: nonce_manager.next(account_address),
        },
    )
    .unwrap();
    assert!(!tx_execution_info.is_reverted());
    assert_eq!(tx_execution_info.actual_fee, Fee(0));
}

// TODO(Dori, 15/9/2023): Convert version variance to attribute macro.
// TODO(Dori, 10/10/2023): Add V3 case once `create_tx_info` is supported for V3.
#[rstest]
fn test_account_flow_test(
    block_context: BlockContext,
    max_fee: Fee,
    #[values(TransactionVersion::ZERO, TransactionVersion::ONE)] tx_version: TransactionVersion,
    #[values(true, false)] only_query: bool,
) {
    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        create_test_init_data(&block_context.chain_info, CairoVersion::Cairo0);

    // Invoke a function from the newly deployed contract.
    run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee,
            sender_address: account_address,
            calldata: create_trivial_calldata(contract_address),
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
// TODO(Nimrod, 10/10/2023): Add V3 case once `get_tx_info` is supported for V3.
fn test_invoke_tx_from_non_deployed_account(
    block_context: BlockContext,
    max_fee: Fee,
    #[case] tx_version: TransactionVersion,
) {
    let TestInitData { mut state, account_address, contract_address: _, mut nonce_manager } =
        create_test_init_data(&block_context.chain_info, CairoVersion::Cairo0);
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
    block_context.versioned_constants.invoke_tx_max_n_steps = 4000;

    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        create_test_init_data(&block_context.chain_info, CairoVersion::Cairo0);

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
// TODO(Aner, 21/01/24) modify test for 4844.
#[rstest]
#[case(TransactionVersion::ONE)]
#[case(TransactionVersion::THREE)]
fn test_max_fee_limit_validate(
    max_fee: Fee,
    block_context: BlockContext,
    #[case] version: TransactionVersion,
    max_resource_bounds: ResourceBoundsMapping,
) {
    let chain_info = &block_context.chain_info;
    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        create_test_init_data(chain_info, CairoVersion::Cairo0);
    let grindy_validate_account = FeatureContract::AccountWithLongValidate(CairoVersion::Cairo0);
    let grindy_class_hash = grindy_validate_account.get_class_hash();
    let block_info = &block_context.block_info;
    let class_info = calculate_class_info_for_testing(grindy_validate_account.get_class());

    // Declare the grindy-validation account.
    let account_tx = declare_tx(
        declare_tx_args! {
            class_hash: grindy_class_hash,
            sender_address: account_address,
            max_fee: Fee(MAX_FEE),
            nonce: nonce_manager.next(account_address),
        },
        class_info,
    );
    account_tx.execute(&mut state, &block_context, true, true).unwrap();

    // Deploy grindy account with a lot of grind in the constructor.
    // Expect this to fail without bumping nonce, so pass a temporary nonce manager.
    let mut ctor_grind_arg = stark_felt!(1_u8); // Grind in deploy phase.
    let ctor_storage_arg = stark_felt!(1_u8); // Not relevant for this test.
    let (deploy_account_tx, _) = deploy_and_fund_account(
        &mut state,
        &mut NonceManager::default(),
        chain_info,
        deploy_account_tx_args! {
            class_hash: grindy_class_hash,
            max_fee,
            constructor_calldata: calldata![ctor_grind_arg, ctor_storage_arg],
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
    ctor_grind_arg = stark_felt!(0_u8); // Do not grind in deploy phase.
    let (deploy_account_tx, grindy_account_address) = deploy_and_fund_account(
        &mut state,
        &mut nonce_manager,
        chain_info,
        deploy_account_tx_args! {
            class_hash: grindy_class_hash,
            max_fee,
            constructor_calldata: calldata![ctor_grind_arg, ctor_storage_arg],
        },
    );
    deploy_account_tx.execute(&mut state, &block_context, true, true).unwrap();

    // Invoke a function that grinds validate (any function will do); set bounds low enough to fail
    // on this grind.
    // To ensure bounds are low enough, estimate minimal resources consumption, and set bounds
    // slightly above them.
    let tx_args = invoke_tx_args! {
        sender_address: grindy_account_address,
        calldata: create_trivial_calldata(contract_address),
        version,
        nonce: nonce_manager.next(grindy_account_address)
    };

    let account_tx = account_invoke_tx(invoke_tx_args! {
        // Temporary upper bounds; just for gas estimation.
        max_fee: Fee(MAX_FEE),
        resource_bounds: max_resource_bounds,
        ..tx_args.clone()
    });
    let estimated_min_gas_usage_vector =
        estimate_minimal_gas_vector(&block_context, &account_tx).unwrap();
    let estimated_min_l1_gas = estimated_min_gas_usage_vector.l1_gas;
    let estimated_min_fee =
        get_fee_by_gas_vector(block_info, estimated_min_gas_usage_vector, &account_tx.fee_type());

    let error = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee: estimated_min_fee,
            // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion
            // works.
            resource_bounds: l1_resource_bounds(
                estimated_min_l1_gas.try_into().expect("Failed to convert u128 to u64."),
                block_info.gas_prices.get_gas_price_by_fee_type(&account_tx.fee_type()).into()
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
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
    block_context: BlockContext,
    max_fee: Fee,
    max_resource_bounds: ResourceBoundsMapping,
) {
    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        create_test_init_data(&block_context.chain_info, cairo_version);

    // Positive test

    // Technical details for this specific recursive entry point:
    // The maximum inner recursion depth is reduced by 2 from the global entry point limit for two
    // reasons:
    // 1. An additional call is made initially before entering the recursion.
    // 2. The base case for recursion occurs at depth 0, not at depth 1.

    // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion works.
    let max_inner_recursion_depth: u8 = (block_context.versioned_constants.max_recursion_depth - 2)
        .try_into()
        .expect("Failed to convert usize to u8.");

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
    let invoke_args = crate::test_utils::invoke::InvokeTxArgs {
        calldata,
        nonce: nonce_manager.next(account_address),
        ..invoke_args
    };
    let tx_execution_info = run_invoke_tx(&mut state, &block_context, invoke_args);

    assert!(tx_execution_info.unwrap().revert_error.unwrap().contains("recursion depth exceeded"));
}

#[rstest]
/// Tests that an account invoke transaction that fails the execution phase, still incurs a nonce
/// increase and a fee deduction.
#[case(TransactionVersion::ONE, FeeType::Eth)]
#[case(TransactionVersion::THREE, FeeType::Strk)]
fn test_revert_invoke(
    block_context: BlockContext,
    max_fee: Fee,
    #[case] transaction_version: TransactionVersion,
    #[case] fee_type: FeeType,
) {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo0);
    let chain_info = &block_context.chain_info;
    let state = &mut test_state(chain_info, BALANCE, &[(test_contract, 1), (account, 1)]);
    let test_contract_address = test_contract.get_instance_address(0);
    let account_address = account.get_instance_address(0);
    let mut nonce_manager = NonceManager::default();

    // Invoke a function that changes the state and reverts.
    let storage_key = stark_felt!(9_u8);
    let tx_execution_info = run_invoke_tx(
        state,
        &block_context,
        invoke_tx_args! {
            max_fee,
            sender_address: account_address,
            calldata: create_calldata(
                test_contract_address,
                "write_and_revert",
                // Write some non-zero value.
                &[storage_key, stark_felt!(99_u8)]
            ),
            version: transaction_version,
            nonce: nonce_manager.next(account_address),
        },
    )
    .unwrap();

    // TODO(Dori, 1/7/2023): Verify that the actual fee collected is exactly the fee computed for
    // the validate and fee transfer calls.

    // Check that the transaction was reverted.
    assert!(tx_execution_info.revert_error.is_some());

    // Check that the nonce was increased and the fee was deducted.
    assert_eq!(
        state
            .get_fee_token_balance(account_address, chain_info.fee_token_address(&fee_type))
            .unwrap(),
        (stark_felt!(BALANCE - tx_execution_info.actual_fee.0), stark_felt!(0_u8))
    );
    assert_eq!(state.get_nonce_at(account_address).unwrap(), nonce_manager.next(account_address));

    // Check that execution state changes were reverted.
    assert_eq!(
        stark_felt!(0_u8),
        state
            .get_storage_at(test_contract_address, StorageKey::try_from(storage_key).unwrap())
            .unwrap()
    );
}

#[rstest]
/// Tests that failing account deployment should not change state (no fee charge or nonce bump).
fn test_fail_deploy_account(
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let chain_info = &block_context.chain_info;
    let faulty_account_feature_contract = FeatureContract::FaultyAccount(cairo_version);
    let state = &mut test_state(chain_info, BALANCE, &[(faulty_account_feature_contract, 0)]);

    // Create and execute (failing) deploy account transaction.
    let deploy_account_tx = create_account_tx_for_validate_test(
        &mut NonceManager::default(),
        FaultyAccountTxCreatorArgs {
            tx_type: TransactionType::DeployAccount,
            scenario: INVALID,
            class_hash: faulty_account_feature_contract.get_class_hash(),
            max_fee: Fee(BALANCE),
            ..Default::default()
        },
    );
    let fee_token_address = chain_info.fee_token_address(&deploy_account_tx.fee_type());

    let deploy_address = match &deploy_account_tx {
        AccountTransaction::DeployAccount(deploy_tx) => deploy_tx.contract_address,
        _ => unreachable!("deploy_account_tx is a DeployAccount"),
    };
    fund_account(chain_info, deploy_address, BALANCE * 2, state);

    let initial_balance = state.get_fee_token_balance(deploy_address, fee_token_address).unwrap();

    let error = deploy_account_tx.execute(state, &block_context, true, true).unwrap_err();
    // Check the error is as expected. Assure the error message is not nonce or fee related.
    check_transaction_execution_error_for_invalid_scenario!(cairo_version, error, false);

    // Assert nonce and balance are unchanged, and that no contract was deployed at the address.
    assert_eq!(state.get_nonce_at(deploy_address).unwrap(), Nonce(stark_felt!(0_u8)));
    assert_eq!(
        state.get_fee_token_balance(deploy_address, fee_token_address).unwrap(),
        initial_balance
    );
    assert_eq!(state.get_class_hash_at(deploy_address).unwrap(), ClassHash::default());
}

#[rstest]
/// Tests that a failing declare transaction should not change state (no fee charge or nonce bump).
fn test_fail_declare(block_context: BlockContext, max_fee: Fee) {
    let chain_info = &block_context.chain_info;
    let TestInitData { mut state, account_address, mut nonce_manager, .. } =
        create_test_init_data(chain_info, CairoVersion::Cairo0);
    let class_hash = class_hash!(0xdeadeadeaf72_u128);
    let contract_class = ContractClass::V1(ContractClassV1::empty_for_testing());
    let next_nonce = nonce_manager.next(account_address);

    // Cannot fail executing a declare tx unless it's V2 or above, and already declared.
    let declare_tx = DeclareTransactionV2 {
        max_fee,
        class_hash,
        sender_address: account_address,
        ..Default::default()
    };
    state.set_contract_class(class_hash, contract_class.clone()).unwrap();
    state.set_compiled_class_hash(class_hash, declare_tx.compiled_class_hash).unwrap();
    let class_info = calculate_class_info_for_testing(contract_class);
    let declare_account_tx = AccountTransaction::Declare(
        DeclareTransaction::new(
            starknet_api::transaction::DeclareTransaction::V2(DeclareTransactionV2 {
                nonce: next_nonce,
                ..declare_tx
            }),
            TransactionHash::default(),
            class_info,
        )
        .unwrap(),
    );

    // Fail execution, assert nonce and balance are unchanged.
    let tx_info = declare_account_tx.create_tx_info();
    let initial_balance = state
        .get_fee_token_balance(account_address, chain_info.fee_token_address(&tx_info.fee_type()))
        .unwrap();
    declare_account_tx.execute(&mut state, &block_context, true, true).unwrap_err();

    assert_eq!(state.get_nonce_at(account_address).unwrap(), next_nonce);
    assert_eq!(
        state
            .get_fee_token_balance(
                account_address,
                chain_info.fee_token_address(&tx_info.fee_type())
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
    mut block_context: BlockContext,
    #[case] version: TransactionVersion,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        create_test_init_data(&block_context.chain_info, cairo_version);

    // Limit the number of execution steps (so we quickly hit the limit).
    block_context.versioned_constants.invoke_tx_max_n_steps = 5000;
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
    // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion works.
    let steps_diff_as_u32: u32 = steps_diff.try_into().expect("Failed to convert usize to u32.");
    let fail_depth = block_context.versioned_constants.invoke_tx_max_n_steps / steps_diff_as_u32;

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
fn test_n_reverted_steps(
    max_fee: Fee,
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        create_test_init_data(&block_context.chain_info, cairo_version);
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
    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        create_test_init_data(&block_context.chain_info, CairoVersion::Cairo0);
    let actual_gas_used = 6065;
    let actual_gas_used_as_u128: u128 = actual_gas_used.into();
    let actual_fee = actual_gas_used_as_u128 * 100000000000;
    let actual_strk_gas_price =
        block_context.block_info.gas_prices.get_gas_price_by_fee_type(&FeeType::Strk);
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
        resource_bounds: l1_resource_bounds(actual_gas_used, actual_strk_gas_price.into()),
        nonce: nonce_manager.next(account_address),
    });
    let tx_context1 = Arc::new(block_context.to_tx_context(&account_tx1));
    let execution_context1 = EntryPointExecutionContext::new_invoke(tx_context1, true).unwrap();
    let max_steps_limit1 = execution_context1.vm_run_resources.get_n_steps();
    let tx_execution_info1 = account_tx1.execute(&mut state, &block_context, true, true).unwrap();
    let n_steps1 = tx_execution_info1.actual_resources.n_steps();
    let gas_used_vector1 = calculate_tx_gas_vector(
        &tx_execution_info1.actual_resources,
        &block_context.versioned_constants,
    )
    .unwrap();

    // Second invocation of `with_arg` gets twice the pre-calculated actual fee as max_fee.
    let account_tx2 = account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(2 * actual_fee),
        sender_address: account_address,
        calldata: execute_calldata,
        version,
        resource_bounds: l1_resource_bounds(2 * actual_gas_used, actual_strk_gas_price.into()),
        nonce: nonce_manager.next(account_address),
    });
    let tx_context2 = Arc::new(block_context.to_tx_context(&account_tx2));
    let execution_context2 = EntryPointExecutionContext::new_invoke(tx_context2, true).unwrap();
    let max_steps_limit2 = execution_context2.vm_run_resources.get_n_steps();
    let tx_execution_info2 = account_tx2.execute(&mut state, &block_context, true, true).unwrap();
    let n_steps2 = tx_execution_info2.actual_resources.n_steps();
    let gas_used_vector2 = calculate_tx_gas_vector(
        &tx_execution_info2.actual_resources,
        &block_context.versioned_constants,
    )
    .unwrap();

    // Test that steps limit doubles as max_fee doubles, but actual consumed steps and fee remains.
    assert_eq!(max_steps_limit2.unwrap(), 2 * max_steps_limit1.unwrap());
    assert_eq!(tx_execution_info1.actual_fee.0, tx_execution_info2.actual_fee.0);
    // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion works.
    // TODO(Aner, 21/01/24): verify test compliant with 4844 (or modify accordingly).
    assert_eq!(
        actual_gas_used,
        u64::try_from(gas_used_vector2.l1_gas).expect("Failed to convert u128 to u64.")
    );
    assert_eq!(actual_fee, tx_execution_info2.actual_fee.0);
    assert_eq!(n_steps1, n_steps2);
    assert_eq!(gas_used_vector1, gas_used_vector2);
}

#[rstest]
/// Tests that transactions with insufficient max_fee are reverted, the correct revert_error is
/// recorded and max_fee is charged.
fn test_insufficient_max_fee_reverts(
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        create_test_init_data(&block_context.chain_info, cairo_version);
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

    // Invoke the `recurse` function with depth of 824 and the actual fee of depth 1 as max_fee.
    // This call should fail due to no remaining steps (execution steps based on max_fee are bounded
    // well enough to catch this mid-execution).
    let tx_execution_info3 = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee: actual_fee_depth1,
            nonce: nonce_manager.next(account_address),
            calldata: recursive_function_calldata(&contract_address, 824, false),
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

#[rstest]
fn test_deploy_account_constructor_storage_write(
    max_fee: Fee,
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let grindy_account = FeatureContract::AccountWithLongValidate(cairo_version);
    let class_hash = grindy_account.get_class_hash();
    let chain_info = &block_context.chain_info;
    let state = &mut test_state(chain_info, BALANCE, &[(grindy_account, 1)]);

    let ctor_storage_arg = stark_felt!(1_u8);
    let ctor_grind_arg = stark_felt!(0_u8); // Do not grind in deploy phase.
    let constructor_calldata = calldata![ctor_grind_arg, ctor_storage_arg];
    let (deploy_account_tx, _) = deploy_and_fund_account(
        state,
        &mut NonceManager::default(),
        chain_info,
        deploy_account_tx_args! {
            class_hash,
            max_fee,
            constructor_calldata: constructor_calldata.clone(),
        },
    );
    deploy_account_tx.execute(state, &block_context, true, true).unwrap();

    // Check that the constructor wrote ctor_arg to the storage.
    let storage_key = get_storage_var_address("ctor_arg", &[]);
    let deployed_contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &constructor_calldata,
        ContractAddress::default(),
    )
    .unwrap();
    let read_storage_arg = state.get_storage_at(deployed_contract_address, storage_key).unwrap();
    assert_eq!(ctor_storage_arg, read_storage_arg);
}

/// Test for counting actual storage changes.
#[rstest]
#[case::tx_version_1(TransactionVersion::ONE, FeeType::Eth)]
#[case::tx_version_3(TransactionVersion::THREE, FeeType::Strk)]
fn test_count_actual_storage_changes(
    max_fee: Fee,
    block_context: BlockContext,
    #[case] version: TransactionVersion,
    #[case] fee_type: FeeType,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    // FeeType according to version.
    let chain_info = &block_context.chain_info;
    let fee_token_address = chain_info.fee_token_address(&fee_type);

    // Create initial state
    let test_contract = FeatureContract::TestContract(cairo_version);
    let account_contract = FeatureContract::AccountWithoutValidations(cairo_version);
    let mut state = test_state(chain_info, BALANCE, &[(account_contract, 1), (test_contract, 1)]);
    let account_address = account_contract.get_instance_address(0);
    let contract_address = test_contract.get_instance_address(0);
    let mut nonce_manager = NonceManager::default();

    let sequencer_address = block_context.block_info.sequencer_address;
    let initial_sequencer_balance = stark_felt_to_felt(
        state.get_fee_token_balance(sequencer_address, fee_token_address).unwrap().0,
    );

    // Fee token var address.
    let sequencer_fee_token_var_address = get_fee_token_var_address(sequencer_address);
    let account_fee_token_var_address = get_fee_token_var_address(account_address);

    // Calldata types.
    let write_1_calldata =
        create_calldata(contract_address, "test_count_actual_storage_changes", &[]);
    let recipient = stark_felt!(435_u16);
    let transfer_amount: Felt252 = 1.into();
    let transfer_calldata = create_calldata(
        fee_token_address,
        TRANSFER_ENTRY_POINT_NAME,
        &[recipient, felt_to_stark_felt(&transfer_amount), stark_felt!(0_u8)],
    );

    // Run transactions; using transactional state to count only storage changes of the current
    // transaction.
    // First transaction: storage cell value changes from 0 to 1.
    let mut state = CachedState::create_transactional(&mut state);
    let invoke_args = invoke_tx_args! {
        max_fee,
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        version,
        sender_address: account_address,
        calldata: write_1_calldata,
        nonce: nonce_manager.next(account_address),
    };
    let account_tx = account_invoke_tx(invoke_args.clone());
    let execution_info = account_tx.execute_raw(&mut state, &block_context, true, true).unwrap();

    let fee_1 = execution_info.actual_fee;
    let state_changes_1 = state.get_actual_state_changes().unwrap();

    let cell_write_storage_change =
        ((contract_address, StorageKey(patricia_key!(15_u8))), stark_felt!(1_u8));
    let mut expected_sequencer_total_fee = initial_sequencer_balance + Felt252::from(fee_1.0);
    let mut expected_sequencer_fee_update = (
        (fee_token_address, sequencer_fee_token_var_address),
        felt_to_stark_felt(&expected_sequencer_total_fee),
    );
    let mut account_balance = BALANCE - fee_1.0;
    let account_balance_storage_change =
        ((fee_token_address, account_fee_token_var_address), stark_felt!(account_balance));

    let expected_modified_contracts =
        HashSet::from([account_address, contract_address, fee_token_address]);
    let expected_storage_updates_1 = HashMap::from([
        cell_write_storage_change,
        account_balance_storage_change,
        expected_sequencer_fee_update,
    ]);

    let state_changes_count_1 =
        state_changes_1.clone().count_for_fee_charge(Some(account_address), fee_token_address);
    let expected_state_changes_count_1 = StateChangesCount {
        // See expected storage updates.
        n_storage_updates: 3,
        // The contract address (storage update) and the account address (nonce update). Does not
        // include the fee token address as a modified contract.
        n_modified_contracts: 2,
        ..Default::default()
    };

    assert_eq!(expected_modified_contracts, state_changes_1.get_modified_contracts());
    assert_eq!(expected_storage_updates_1, state_changes_1.storage_updates);
    assert_eq!(state_changes_count_1, expected_state_changes_count_1);

    // Second transaction: storage cell starts and ends with value 1.
    let mut state = CachedState::create_transactional(&mut state);
    let account_tx = account_invoke_tx(InvokeTxArgs {
        nonce: nonce_manager.next(account_address),
        ..invoke_args.clone()
    });
    let execution_info = account_tx.execute_raw(&mut state, &block_context, true, true).unwrap();

    let fee_2 = execution_info.actual_fee;
    let state_changes_2 = state.get_actual_state_changes().unwrap();

    expected_sequencer_total_fee += Felt252::from(fee_2.0);
    expected_sequencer_fee_update.1 = felt_to_stark_felt(&expected_sequencer_total_fee);
    account_balance -= fee_2.0;
    let account_balance_storage_change =
        ((fee_token_address, account_fee_token_var_address), stark_felt!(account_balance));

    let expected_modified_contracts_2 = HashSet::from([account_address, fee_token_address]);
    let expected_storage_updates_2 =
        HashMap::from([account_balance_storage_change, expected_sequencer_fee_update]);

    let state_changes_count_2 =
        state_changes_2.clone().count_for_fee_charge(Some(account_address), fee_token_address);
    let expected_state_changes_count_2 = StateChangesCount {
        // See expected storage updates.
        n_storage_updates: 2,
        // The account address (nonce update). Does not include the fee token address as a modified
        // contract.
        n_modified_contracts: 1,
        ..Default::default()
    };

    assert_eq!(expected_modified_contracts_2, state_changes_2.get_modified_contracts());
    assert_eq!(expected_storage_updates_2, state_changes_2.storage_updates);
    assert_eq!(state_changes_count_2, expected_state_changes_count_2);

    // Transfer transaction: transfer 1 ETH to recepient.
    let mut state = CachedState::create_transactional(&mut state);
    let account_tx = account_invoke_tx(InvokeTxArgs {
        nonce: nonce_manager.next(account_address),
        calldata: transfer_calldata,
        ..invoke_args
    });
    let execution_info = account_tx.execute_raw(&mut state, &block_context, true, true).unwrap();

    let fee_transfer = execution_info.actual_fee;
    let state_changes_transfer = state.get_actual_state_changes().unwrap();
    let transfer_receipient_storage_change = (
        (fee_token_address, get_fee_token_var_address(contract_address!(recipient))),
        felt_to_stark_felt(&transfer_amount),
    );

    expected_sequencer_total_fee += Felt252::from(fee_transfer.0);
    expected_sequencer_fee_update.1 = felt_to_stark_felt(&expected_sequencer_total_fee);
    account_balance -= fee_transfer.0 + 1; // Reduce the fee and the transfered amount (1).
    let account_balance_storage_change =
        ((fee_token_address, account_fee_token_var_address), stark_felt!(account_balance));

    let expected_modified_contracts_transfer = HashSet::from([account_address, fee_token_address]);
    let expected_storage_update_transfer = HashMap::from([
        transfer_receipient_storage_change,
        account_balance_storage_change,
        expected_sequencer_fee_update,
    ]);

    let state_changes_count_3 = state_changes_transfer
        .clone()
        .count_for_fee_charge(Some(account_address), fee_token_address);
    let expected_state_changes_count_3 = StateChangesCount {
        // See expected storage updates.
        n_storage_updates: 3,
        // The account address (nonce update). Does not include the fee token address as a modified
        // contract.
        n_modified_contracts: 1,
        ..Default::default()
    };

    assert_eq!(
        expected_modified_contracts_transfer,
        state_changes_transfer.get_modified_contracts()
    );
    assert_eq!(expected_storage_update_transfer, state_changes_transfer.storage_updates);
    assert_eq!(state_changes_count_3, expected_state_changes_count_3);
}
