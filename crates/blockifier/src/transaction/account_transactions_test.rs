use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cairo_vm::vm::runners::cairo_runner::ResourceTracker;
use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransactionV2, Fee, ResourceBoundsMapping,
    TransactionHash, TransactionVersion,
};
use starknet_api::{calldata, class_hash, contract_address, felt, patricia_key};
use starknet_types_core::felt::Felt;

use crate::abi::abi_utils::{
    get_fee_token_var_address, get_storage_var_address, selector_from_name,
};
use crate::context::BlockContext;
use crate::execution::contract_class::{ContractClass, ContractClassV1};
use crate::execution::entry_point::EntryPointExecutionContext;
use crate::execution::syscalls::SyscallSelector;
use crate::fee::fee_utils::{get_fee_by_gas_vector, get_sequencer_balance_keys};
use crate::fee::gas_usage::estimate_minimal_gas_vector;
use crate::state::cached_state::{StateChangesCount, TransactionalState};
use crate::state::state_api::{State, StateReader};
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::declare::declare_tx;
use crate::test_utils::deploy_account::deploy_account_tx;
use crate::test_utils::initial_test_state::{fund_account, test_state};
use crate::test_utils::invoke::InvokeTxArgs;
use crate::test_utils::{
    create_calldata, create_trivial_calldata, get_syscall_resources, get_tx_resources,
    u64_from_usize, CairoVersion, NonceManager, BALANCE, DEFAULT_STRK_L1_GAS_PRICE, MAX_FEE,
};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants::TRANSFER_ENTRY_POINT_NAME;
use crate::transaction::objects::{FeeType, GasVector, HasRelatedFeeType, TransactionInfoCreator};
use crate::transaction::test_utils::{
    account_invoke_tx, block_context, calculate_class_info_for_testing,
    create_account_tx_for_validate_test_nonce_0, create_test_init_data, deploy_and_fund_account,
    l1_resource_bounds, max_fee, max_resource_bounds, run_invoke_tx, FaultyAccountTxCreatorArgs,
    TestInitData, INVALID,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transactions::{DeclareTransaction, ExecutableTransaction, ExecutionFlags};
use crate::{
    check_transaction_execution_error_for_invalid_scenario, declare_tx_args,
    deploy_account_tx_args, invoke_tx_args, nonce, storage_key,
};

#[rstest]
fn test_circuit(block_context: BlockContext, max_resource_bounds: ResourceBoundsMapping) {
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let chain_info = &block_context.chain_info;
    let state = &mut test_state(chain_info, BALANCE, &[(test_contract, 1), (account, 1)]);
    let test_contract_address = test_contract.get_instance_address(0);
    let account_address = account.get_instance_address(0);
    let mut nonce_manager = NonceManager::default();

    // Invoke a function that changes the state and reverts.
    let tx_args = invoke_tx_args! {
        sender_address: account_address,
        calldata: create_calldata(
                test_contract_address,
                "test_circuit",
                &[]
            ),
        nonce: nonce_manager.next(account_address)
    };
    let tx_execution_info = run_invoke_tx(
        state,
        &block_context,
        invoke_tx_args! {
            resource_bounds: max_resource_bounds,
            ..tx_args
        },
    )
    .unwrap();

    assert!(tx_execution_info.revert_error.is_none());
    assert_eq!(tx_execution_info.transaction_receipt.gas, GasVector::from_l1_gas(6682));
}

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
    assert_eq!(tx_execution_info.transaction_receipt.fee, Fee(0));
}

// TODO(Dori, 15/9/2023): Convert version variance to attribute macro.
#[rstest]
fn test_account_flow_test(
    block_context: BlockContext,
    max_fee: Fee,
    max_resource_bounds: ResourceBoundsMapping,
    #[values(TransactionVersion::ZERO, TransactionVersion::ONE, TransactionVersion::THREE)]
    tx_version: TransactionVersion,
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
            resource_bounds: max_resource_bounds,
            nonce: nonce_manager.next(account_address),
            only_query,
        },
    )
    .unwrap();
}

#[rstest]
#[case(TransactionVersion::ZERO)]
#[case(TransactionVersion::ONE)]
#[case(TransactionVersion::THREE)]
fn test_invoke_tx_from_non_deployed_account(
    block_context: BlockContext,
    max_fee: Fee,
    max_resource_bounds: ResourceBoundsMapping,
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
                felt!(1_u8),         // Calldata length.
                felt!(2_u8)          // Calldata: num.
            ],
            resource_bounds: max_resource_bounds,
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
            assert!(err.to_string().contains(expected_error));
            // We expect to get an error only when tx_version is 0, on other versions to revert.
            assert_eq!(tx_version, TransactionVersion::ZERO);
        }
    }
}

#[rstest]
// Try two runs for each recursion type: one short run (success), and one that reverts due to step
// limit.
fn test_infinite_recursion(
    #[values(true, false)] success: bool,
    #[values(true, false)] normal_recurse: bool,
    mut block_context: BlockContext,
    max_resource_bounds: ResourceBoundsMapping,
) {
    // Limit the number of execution steps (so we quickly hit the limit).
    block_context.versioned_constants.invoke_tx_max_n_steps = 4100;

    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        create_test_init_data(&block_context.chain_info, CairoVersion::Cairo0);

    let recursion_depth = if success { 3_u32 } else { 1000_u32 };

    let execute_calldata = if normal_recurse {
        create_calldata(contract_address, "recurse", &[felt!(recursion_depth)])
    } else {
        create_calldata(
            contract_address,
            "recursive_syscall",
            &[
                *contract_address.0.key(), // Calldata: raw contract address.
                selector_from_name("recursive_syscall").0, // Calldata: raw selector
                felt!(recursion_depth),
            ],
        )
    };

    let tx_execution_info = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            resource_bounds: max_resource_bounds,
            sender_address: account_address,
            calldata: execute_calldata,
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
    block_context: BlockContext,
    #[case] version: TransactionVersion,
    max_resource_bounds: ResourceBoundsMapping,
) {
    let chain_info = &block_context.chain_info;
    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        create_test_init_data(chain_info, CairoVersion::Cairo1);
    let grindy_validate_account = FeatureContract::AccountWithLongValidate(CairoVersion::Cairo1);
    let grindy_class_hash = grindy_validate_account.get_class_hash();
    let block_info = &block_context.block_info;
    let class_info = calculate_class_info_for_testing(grindy_validate_account.get_class());

    // Declare the grindy-validation account.
    let account_tx = declare_tx(
        declare_tx_args! {
            class_hash: grindy_class_hash,
            sender_address: account_address,
            resource_bounds: max_resource_bounds.clone(),
            nonce: nonce_manager.next(account_address),
        },
        class_info,
    );
    account_tx.execute(&mut state, &block_context, true, true).unwrap();

    // Deploy grindy account with a lot of grind in the constructor.
    // Expect this to fail without bumping nonce, so pass a temporary nonce manager.
    let mut ctor_grind_arg = felt!(1_u8); // Grind in deploy phase.
    let ctor_storage_arg = felt!(1_u8); // Not relevant for this test.
    let (deploy_account_tx, _) = deploy_and_fund_account(
        &mut state,
        &mut NonceManager::default(),
        chain_info,
        deploy_account_tx_args! {
            class_hash: grindy_class_hash,
            resource_bounds: max_resource_bounds.clone(),
            constructor_calldata: calldata![ctor_grind_arg, ctor_storage_arg],
        },
    );
    let error_trace =
        deploy_account_tx.execute(&mut state, &block_context, true, true).unwrap_err().to_string();
    assert!(error_trace.contains("no remaining steps"));

    // Deploy grindy account successfully this time.
    ctor_grind_arg = felt!(0_u8); // Do not grind in deploy phase.
    let (deploy_account_tx, grindy_account_address) = deploy_and_fund_account(
        &mut state,
        &mut nonce_manager,
        chain_info,
        deploy_account_tx_args! {
            class_hash: grindy_class_hash,
            resource_bounds: max_resource_bounds.clone(),
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

    let error_trace = run_invoke_tx(
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
    .unwrap_err()
    .to_string();

    assert!(error_trace.contains("no remaining steps"));
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
            felt!(max_inner_recursion_depth),
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
            felt!(exceeding_recursion_depth),
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
    let storage_key = felt!(9_u8);
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
                &[storage_key, felt!(99_u8)]
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
        (felt!(BALANCE - tx_execution_info.transaction_receipt.fee.0), felt!(0_u8))
    );
    assert_eq!(state.get_nonce_at(account_address).unwrap(), nonce_manager.next(account_address));

    // Check that reverted steps are taken into account.
    assert!(tx_execution_info.transaction_receipt.resources.n_reverted_steps > 0);

    // Check that execution state changes were reverted.
    assert_eq!(
        felt!(0_u8),
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
    #[values(TransactionVersion::ONE, TransactionVersion::THREE)] tx_version: TransactionVersion,
) {
    let chain_info = &block_context.chain_info;
    let faulty_account_feature_contract = FeatureContract::FaultyAccount(cairo_version);
    let state = &mut test_state(chain_info, BALANCE, &[(faulty_account_feature_contract, 0)]);

    // Create and execute (failing) deploy account transaction.
    let deploy_account_tx =
        create_account_tx_for_validate_test_nonce_0(FaultyAccountTxCreatorArgs {
            tx_type: TransactionType::DeployAccount,
            tx_version,
            scenario: INVALID,
            class_hash: faulty_account_feature_contract.get_class_hash(),
            max_fee: Fee(BALANCE),
            ..Default::default()
        });
    let fee_token_address = chain_info.fee_token_address(&deploy_account_tx.fee_type());

    let deploy_address = match &deploy_account_tx {
        AccountTransaction::DeployAccount(deploy_tx) => deploy_tx.contract_address,
        _ => unreachable!("deploy_account_tx is a DeployAccount"),
    };
    fund_account(chain_info, deploy_address, BALANCE * 2, &mut state.state);

    let initial_balance = state.get_fee_token_balance(deploy_address, fee_token_address).unwrap();

    let error = deploy_account_tx.execute(state, &block_context, true, true).unwrap_err();
    // Check the error is as expected. Assure the error message is not nonce or fee related.
    check_transaction_execution_error_for_invalid_scenario!(cairo_version, error, false);

    // Assert nonce and balance are unchanged, and that no contract was deployed at the address.
    assert_eq!(state.get_nonce_at(deploy_address).unwrap(), nonce!(0_u8));
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
        &[felt!(depth)], // Calldata: recursion depth.
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
    let n_steps_0 = result.transaction_receipt.resources.total_charged_steps();
    let actual_fee_0 = result.transaction_receipt.fee.0;
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
    let n_steps_1 = result.transaction_receipt.resources.total_charged_steps();
    let actual_fee_1 = result.transaction_receipt.fee.0;
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
    let n_steps_fail = result.transaction_receipt.resources.total_charged_steps();
    let actual_fee_fail: u128 = result.transaction_receipt.fee.0;
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
    let n_steps_fail_next = result.transaction_receipt.resources.total_charged_steps();
    let actual_fee_fail_next: u128 = result.transaction_receipt.fee.0;
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
    block_context: BlockContext,
    max_resource_bounds: ResourceBoundsMapping,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        create_test_init_data(&block_context.chain_info, cairo_version);
    let recursion_base_args = invoke_tx_args! {
        resource_bounds: max_resource_bounds,
        sender_address: account_address,
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
    let mut actual_resources_0 = result.transaction_receipt.resources.clone();
    let n_steps_0 = result.transaction_receipt.resources.total_charged_steps();
    let actual_fee_0 = result.transaction_receipt.fee.0;

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
    let actual_resources_1 = result.transaction_receipt.resources;
    let n_steps_1 = actual_resources_1.total_charged_steps();
    let actual_fee_1 = result.transaction_receipt.fee.0;

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
    let n_steps_2 = result.transaction_receipt.resources.total_charged_steps();
    let actual_fee_2 = result.transaction_receipt.fee.0;
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
    actual_resources_0.n_reverted_steps += single_call_steps_delta;
    assert_eq!(actual_resources_0, actual_resources_1);
    actual_resources_0.vm_resources.n_steps = n_steps_0;

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
    let n_steps_100 = result.transaction_receipt.resources.total_charged_steps();
    let actual_fee_100 = result.transaction_receipt.fee.0;
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
    let actual_gas_used: u64 = u64_from_usize(
        get_syscall_resources(SyscallSelector::CallContract).n_steps
            + get_tx_resources(TransactionType::InvokeFunction).n_steps
            + 1751,
    );
    let actual_gas_used_as_u128: u128 = actual_gas_used.into();
    let actual_fee = actual_gas_used_as_u128 * 100000000000;
    let actual_strk_gas_price =
        block_context.block_info.gas_prices.get_gas_price_by_fee_type(&FeeType::Strk);
    let execute_calldata = create_calldata(
        contract_address,
        "with_arg",
        &[felt!(25_u8)], // Calldata: arg.
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
    let n_steps1 = tx_execution_info1.transaction_receipt.resources.vm_resources.n_steps;
    let gas_used_vector1 = tx_execution_info1
        .transaction_receipt
        .resources
        .to_gas_vector(&block_context.versioned_constants, block_context.block_info.use_kzg_da)
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
    let n_steps2 = tx_execution_info2.transaction_receipt.resources.vm_resources.n_steps;
    let gas_used_vector2 = tx_execution_info2
        .transaction_receipt
        .resources
        .to_gas_vector(&block_context.versioned_constants, block_context.block_info.use_kzg_da)
        .unwrap();

    // Test that steps limit doubles as max_fee doubles, but actual consumed steps and fee remains.
    assert_eq!(max_steps_limit2.unwrap(), 2 * max_steps_limit1.unwrap());
    assert_eq!(
        tx_execution_info1.transaction_receipt.fee.0,
        tx_execution_info2.transaction_receipt.fee.0
    );
    // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion works.
    // TODO(Aner, 21/01/24): verify test compliant with 4844 (or modify accordingly).
    assert_eq!(
        actual_gas_used,
        u64::try_from(gas_used_vector2.l1_gas).expect("Failed to convert u128 to u64.")
    );
    assert_eq!(actual_fee, tx_execution_info2.transaction_receipt.fee.0);
    assert_eq!(n_steps1, n_steps2);
    assert_eq!(gas_used_vector1, gas_used_vector2);
}

#[rstest]
/// Tests that transactions with insufficient max_fee are reverted, the correct revert_error is
/// recorded and max_fee is charged.
fn test_insufficient_max_fee_reverts(
    block_context: BlockContext,
    max_resource_bounds: ResourceBoundsMapping,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        create_test_init_data(&block_context.chain_info, cairo_version);
    let recursion_base_args = invoke_tx_args! {
        sender_address: account_address,
    };

    // Invoke the `recurse` function with depth 1 and MAX_FEE. This call should succeed.
    let tx_execution_info1 = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            resource_bounds: max_resource_bounds,
            nonce: nonce_manager.next(account_address),
            calldata: recursive_function_calldata(&contract_address, 1, false),
            ..recursion_base_args.clone()
        },
    )
    .unwrap();
    assert!(!tx_execution_info1.is_reverted());
    let actual_fee_depth1 = tx_execution_info1.transaction_receipt.fee;
    let gas_price = u128::from(block_context.block_info.gas_prices.strk_l1_gas_price);
    let gas_ammount = u64::try_from(actual_fee_depth1.0 / gas_price).unwrap();

    // Invoke the `recurse` function with depth of 2 and the actual fee of depth 1 as max_fee.
    // This call should fail due to insufficient max fee (steps bound based on max_fee is not so
    // tight as to stop execution between iterations 1 and 2).
    let tx_execution_info2 = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            resource_bounds: l1_resource_bounds(gas_ammount, gas_price),
            nonce: nonce_manager.next(account_address),
            calldata: recursive_function_calldata(&contract_address, 2, false),
            ..recursion_base_args.clone()
        },
    )
    .unwrap();
    assert!(tx_execution_info2.is_reverted());
    assert!(tx_execution_info2.transaction_receipt.fee == actual_fee_depth1);
    assert!(tx_execution_info2.revert_error.unwrap().starts_with("Insufficient max L1 gas:"));

    // Invoke the `recurse` function with depth of 824 and the actual fee of depth 1 as max_fee.
    // This call should fail due to no remaining steps (execution steps based on max_fee are bounded
    // well enough to catch this mid-execution).
    let tx_execution_info3 = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            resource_bounds: l1_resource_bounds(gas_ammount, gas_price),
            nonce: nonce_manager.next(account_address),
            calldata: recursive_function_calldata(&contract_address, 824, false),
            ..recursion_base_args
        },
    )
    .unwrap();
    assert!(tx_execution_info3.is_reverted());
    assert!(tx_execution_info3.transaction_receipt.fee == actual_fee_depth1);
    assert!(
        tx_execution_info3.revert_error.unwrap().contains("RunResources has no remaining steps.")
    );
}

#[rstest]
fn test_deploy_account_constructor_storage_write(
    max_resource_bounds: ResourceBoundsMapping,
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let grindy_account = FeatureContract::AccountWithLongValidate(cairo_version);
    let class_hash = grindy_account.get_class_hash();
    let chain_info = &block_context.chain_info;
    let state = &mut test_state(chain_info, BALANCE, &[(grindy_account, 1)]);

    let ctor_storage_arg = felt!(1_u8);
    let ctor_grind_arg = felt!(0_u8); // Do not grind in deploy phase.
    let constructor_calldata = calldata![ctor_grind_arg, ctor_storage_arg];
    let (deploy_account_tx, _) = deploy_and_fund_account(
        state,
        &mut NonceManager::default(),
        chain_info,
        deploy_account_tx_args! {
            class_hash,
            resource_bounds: max_resource_bounds,
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
    max_resource_bounds: ResourceBoundsMapping,
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
    let initial_sequencer_balance =
        state.get_fee_token_balance(sequencer_address, fee_token_address).unwrap().0;

    // Fee token var address.
    let sequencer_fee_token_var_address = get_fee_token_var_address(sequencer_address);
    let account_fee_token_var_address = get_fee_token_var_address(account_address);

    // Calldata types.
    let write_1_calldata =
        create_calldata(contract_address, "test_count_actual_storage_changes", &[]);
    let recipient = 435_u16;
    let transfer_amount: Felt = 1.into();
    let transfer_calldata = create_calldata(
        fee_token_address,
        TRANSFER_ENTRY_POINT_NAME,
        &[felt!(recipient), transfer_amount, felt!(0_u8)],
    );

    // Run transactions; using transactional state to count only storage changes of the current
    // transaction.
    // First transaction: storage cell value changes from 0 to 1.
    let mut state = TransactionalState::create_transactional(&mut state);
    let invoke_args = invoke_tx_args! {
        max_fee,
        resource_bounds: max_resource_bounds,
        version,
        sender_address: account_address,
        calldata: write_1_calldata,
        nonce: nonce_manager.next(account_address),
    };
    let account_tx = account_invoke_tx(invoke_args.clone());
    let execution_flags =
        ExecutionFlags { charge_fee: true, validate: true, concurrency_mode: false };
    let execution_info =
        account_tx.execute_raw(&mut state, &block_context, execution_flags).unwrap();

    let fee_1 = execution_info.transaction_receipt.fee;
    let state_changes_1 = state.get_actual_state_changes().unwrap();

    let cell_write_storage_change = ((contract_address, storage_key!(15_u8)), felt!(1_u8));
    let mut expected_sequencer_total_fee = initial_sequencer_balance + Felt::from(fee_1.0);
    let mut expected_sequencer_fee_update =
        ((fee_token_address, sequencer_fee_token_var_address), expected_sequencer_total_fee);
    let mut account_balance = BALANCE - fee_1.0;
    let account_balance_storage_change =
        ((fee_token_address, account_fee_token_var_address), felt!(account_balance));

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
    assert_eq!(expected_storage_updates_1, state_changes_1.0.storage);
    assert_eq!(state_changes_count_1, expected_state_changes_count_1);

    // Second transaction: storage cell starts and ends with value 1.
    let mut state = TransactionalState::create_transactional(&mut state);
    let account_tx = account_invoke_tx(InvokeTxArgs {
        nonce: nonce_manager.next(account_address),
        ..invoke_args.clone()
    });
    let execution_info =
        account_tx.execute_raw(&mut state, &block_context, execution_flags).unwrap();

    let fee_2 = execution_info.transaction_receipt.fee;
    let state_changes_2 = state.get_actual_state_changes().unwrap();

    expected_sequencer_total_fee += Felt::from(fee_2.0);
    expected_sequencer_fee_update.1 = expected_sequencer_total_fee;
    account_balance -= fee_2.0;
    let account_balance_storage_change =
        ((fee_token_address, account_fee_token_var_address), felt!(account_balance));

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
    assert_eq!(expected_storage_updates_2, state_changes_2.0.storage);
    assert_eq!(state_changes_count_2, expected_state_changes_count_2);

    // Transfer transaction: transfer 1 ETH to recepient.
    let mut state = TransactionalState::create_transactional(&mut state);
    let account_tx = account_invoke_tx(InvokeTxArgs {
        nonce: nonce_manager.next(account_address),
        calldata: transfer_calldata,
        ..invoke_args
    });
    let execution_info =
        account_tx.execute_raw(&mut state, &block_context, execution_flags).unwrap();

    let fee_transfer = execution_info.transaction_receipt.fee;
    let state_changes_transfer = state.get_actual_state_changes().unwrap();
    let transfer_receipient_storage_change = (
        (fee_token_address, get_fee_token_var_address(contract_address!(recipient))),
        transfer_amount,
    );

    expected_sequencer_total_fee += Felt::from(fee_transfer.0);
    expected_sequencer_fee_update.1 = expected_sequencer_total_fee;
    account_balance -= fee_transfer.0 + 1; // Reduce the fee and the transfered amount (1).
    let account_balance_storage_change =
        ((fee_token_address, account_fee_token_var_address), felt!(account_balance));

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
    assert_eq!(expected_storage_update_transfer, state_changes_transfer.0.storage);
    assert_eq!(state_changes_count_3, expected_state_changes_count_3);
}

#[rstest]
#[case::tx_version_1(TransactionVersion::ONE)]
#[case::tx_version_3(TransactionVersion::THREE)]
fn test_concurrency_execute_fee_transfer(
    max_fee: Fee,
    max_resource_bounds: ResourceBoundsMapping,
    #[case] version: TransactionVersion,
) {
    // TODO(Meshi, 01/06/2024): make the test so it will include changes in
    // sequencer_balance_key_high.
    const TRANSFER_AMOUNT: u128 = 100;
    const SEQUENCER_BALANCE_LOW_INITIAL: u128 = 50;

    let block_context = BlockContext::create_for_account_testing();
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let chain_info = &block_context.chain_info;
    let state = &mut test_state(chain_info, BALANCE, &[(account, 1), (test_contract, 1)]);
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(&block_context);
    let account_tx = account_invoke_tx(invoke_tx_args! {
    sender_address: account.get_instance_address(0),
    max_fee,
    calldata: create_trivial_calldata(test_contract.get_instance_address(0)),
    resource_bounds: max_resource_bounds.clone(),
    version
    });
    let fee_type = &account_tx.fee_type();
    let fee_token_address = block_context.chain_info.fee_token_address(fee_type);

    // Case 1: The transaction did not read form/ write to the sequenser balance before executing
    // fee transfer.
    let mut transactional_state = TransactionalState::create_transactional(state);
    let execution_flags =
        ExecutionFlags { charge_fee: true, validate: true, concurrency_mode: true };
    let result =
        account_tx.execute_raw(&mut transactional_state, &block_context, execution_flags).unwrap();
    assert!(!result.is_reverted());
    let transactional_cache = transactional_state.cache.borrow();
    for storage in [
        transactional_cache.initial_reads.storage.clone(),
        transactional_cache.writes.storage.clone(),
    ] {
        for seq_key in [sequencer_balance_key_low, sequencer_balance_key_high] {
            assert!(!storage.contains_key(&(fee_token_address, seq_key)));
        }
    }

    // Case 2: The transaction read from and write to the sequenser balance before executing fee
    // transfer.

    let transfer_calldata = create_calldata(
        fee_token_address,
        TRANSFER_ENTRY_POINT_NAME,
        &[*block_context.block_info.sequencer_address.0.key(), felt!(TRANSFER_AMOUNT), felt!(0_u8)],
    );

    // Set the sequencer balance to a constant value to check that the read set did not changed.
    fund_account(
        chain_info,
        block_context.block_info.sequencer_address,
        SEQUENCER_BALANCE_LOW_INITIAL,
        &mut state.state,
    );
    let mut transactional_state = TransactionalState::create_transactional(state);

    // Invokes transfer to the sequencer.
    let account_tx = account_invoke_tx(invoke_tx_args! {
        sender_address: account.get_instance_address(0),
        calldata: transfer_calldata,
        max_fee,
        resource_bounds: max_resource_bounds,
    });

    let execution_result =
        account_tx.execute_raw(&mut transactional_state, &block_context, execution_flags);
    let result = execution_result.unwrap();
    assert!(!result.is_reverted());
    // Check that the sequencer balance was not updated.
    let storage_writes = transactional_state.cache.borrow().writes.storage.clone();
    let storage_initial_reads = transactional_state.cache.borrow().initial_reads.storage.clone();

    for (seq_write_val, expexted_write_val) in [
        (
            storage_writes.get(&(fee_token_address, sequencer_balance_key_low)),
            // Balance after `execute` and without the fee transfer.
            felt!(SEQUENCER_BALANCE_LOW_INITIAL + TRANSFER_AMOUNT),
        ),
        (
            storage_initial_reads.get(&(fee_token_address, sequencer_balance_key_low)),
            felt!(SEQUENCER_BALANCE_LOW_INITIAL),
        ),
        (storage_writes.get(&(fee_token_address, sequencer_balance_key_high)), Felt::ZERO),
        (storage_initial_reads.get(&(fee_token_address, sequencer_balance_key_high)), Felt::ZERO),
    ] {
        assert_eq!(*seq_write_val.unwrap(), expexted_write_val);
    }
}

// Check that when the sequencer is the sender, we run the sequential fee transfer.
#[rstest]
#[case::tx_version_1(TransactionVersion::ONE)]
#[case::tx_version_3(TransactionVersion::THREE)]
fn test_concurrent_fee_transfer_when_sender_is_sequencer(
    max_fee: Fee,
    max_resource_bounds: ResourceBoundsMapping,
    #[case] version: TransactionVersion,
) {
    let mut block_context = BlockContext::create_for_account_testing();
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let account_address = account.get_instance_address(0_u16);
    block_context.block_info.sequencer_address = account_address;
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let sender_balance = BALANCE;
    let chain_info = &block_context.chain_info;
    let state = &mut test_state(chain_info, sender_balance, &[(account, 1), (test_contract, 1)]);
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(&block_context);
    let account_tx = account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: account_address,
        calldata: create_trivial_calldata(test_contract.get_instance_address(0)),
        resource_bounds: max_resource_bounds,
        version
    });
    let fee_type = &account_tx.fee_type();
    let fee_token_address = block_context.chain_info.fee_token_address(fee_type);

    let mut transactional_state = TransactionalState::create_transactional(state);
    let execution_flags =
        ExecutionFlags { charge_fee: true, validate: true, concurrency_mode: true };
    let result =
        account_tx.execute_raw(&mut transactional_state, &block_context, execution_flags).unwrap();
    assert!(!result.is_reverted());
    // Check that the sequencer balance was updated (in this case, was not changed).
    for (seq_key, seq_value) in
        [(sequencer_balance_key_low, sender_balance), (sequencer_balance_key_high, 0_u128)]
    {
        assert_eq!(state.get_storage_at(fee_token_address, seq_key).unwrap(), felt!(seq_value));
    }
}
