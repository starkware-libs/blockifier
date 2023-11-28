use assert_matches::assert_matches;
use cairo_felt::Felt252;
use rstest::rstest;
use starknet_api::core::{ContractAddress, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{Calldata, Fee, TransactionSignature, TransactionVersion};
use starknet_api::{calldata, contract_address, patricia_key, stark_felt};

use crate::abi::abi_utils::selector_from_name;
use crate::block_context::BlockContext;
use crate::execution::errors::EntryPointExecutionError;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::eth_gas_constants;
use crate::fee::fee_utils::{calculate_tx_fee, calculate_tx_l1_gas_usage, get_fee_by_l1_gas_usage};
use crate::invoke_tx_args;
use crate::state::cached_state::CachedState;
use crate::state::state_api::StateReader;
use crate::test_utils::{
    create_calldata, InvokeTxArgs, BALANCE, MAX_FEE, MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE,
    TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS,
};
use crate::transaction::errors::{
    TransactionExecutionError, TransactionFeeError, TransactionPreValidationError,
};
use crate::transaction::objects::{FeeType, TransactionExecutionInfo};
use crate::transaction::test_utils::{
    account_invoke_tx, create_state_with_falliable_validation_account, create_test_init_data,
    l1_resource_bounds, TestInitData, INVALID,
};
use crate::transaction::transactions::ExecutableTransaction;

const VALIDATE_GAS_OVERHEAD: u64 = 21;

/// Checks that balance of the account decreased if and only if `charge_fee` is true.
/// Returns the new balance.
fn check_balance<S: StateReader>(
    current_balance: StarkFelt,
    state: &mut CachedState<S>,
    account_address: ContractAddress,
    block_context: &BlockContext,
    fee_type: &FeeType,
    charge_fee: bool,
) -> StarkFelt {
    let (new_balance, _) = state
        .get_fee_token_balance(&account_address, &block_context.fee_token_address(fee_type))
        .unwrap();
    if charge_fee {
        assert!(new_balance < current_balance);
    } else {
        assert_eq!(new_balance, current_balance);
    }
    new_balance
}

/// Returns the amount of L1 gas and derived fee, given base gas amount and a boolean indicating
/// if validation is to be done.
fn gas_and_fee(base_gas: u64, validate_mode: bool, fee_type: &FeeType) -> (u64, Fee) {
    // Validation incurs a constant gas overhead.
    let gas = base_gas + if validate_mode { VALIDATE_GAS_OVERHEAD } else { 0 };
    (
        gas,
        get_fee_by_l1_gas_usage(&BlockContext::create_for_account_testing(), gas as u128, fee_type),
    )
}

/// Asserts gas used and reported fee are as expected.
/// Actual fee is not necessarily the cost of the actual resources; check them separately.
fn check_gas_and_fee(
    block_context: &BlockContext,
    tx_execution_info: &TransactionExecutionInfo,
    expected_actual_gas: u64,
    expected_actual_fee: Fee,
) {
    assert_eq!(
        calculate_tx_l1_gas_usage(&tx_execution_info.actual_resources, block_context).unwrap(),
        expected_actual_gas as u128
    );
    assert_eq!(tx_execution_info.actual_fee, expected_actual_fee);
}

fn recurse_calldata(contract_address: ContractAddress, fail: bool, depth: u32) -> Calldata {
    create_calldata(
        contract_address,
        if fail { "recursive_fail" } else { "recurse" },
        &[stark_felt!(depth)],
    )
}

/// Test simulate / validate / charge_fee flag combinations in pre-validation stage.
#[rstest]
#[case(TransactionVersion::ONE, FeeType::Eth, true)]
#[case(TransactionVersion::THREE, FeeType::Strk, false)]
fn test_simulate_validate_charge_fee_pre_validate(
    #[values(true, false)] only_query: bool,
    #[values(true, false)] validate: bool,
    #[values(true, false)] charge_fee: bool,
    #[case] version: TransactionVersion,
    #[case] fee_type: FeeType,
    #[case] is_deprecated: bool,
) {
    let block_context = BlockContext::create_for_account_testing();
    let max_fee = Fee(MAX_FEE);
    let gas_price = block_context.gas_prices.get_by_fee_type(&fee_type);
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(max_fee, block_context);

    // Pre-validation scenarios.
    // 1. Invalid nonce.
    // 2. Not enough resource bounds for minimal fee.
    // 3. Not enough balance for resource bounds.
    // 4. Max L1 gas price is too low (non-deprecated transactions only).
    // In all scenarios, no need for balance check - balance shouldn't change regardless of flags.
    let pre_validation_base_args = invoke_tx_args! {
        max_fee,
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        sender_address: account_address,
        calldata: calldata![
            *contract_address.0.key(),              // Contract address.
            selector_from_name("return_result").0,  // EP selector.
            stark_felt!(1_u8),                      // Calldata length.
            stark_felt!(2_u8)                       // Calldata: num.
        ],
        version,
        only_query,
    };

    // First scenario: invalid nonce. Regardless of flags, should fail.
    let invalid_nonce = Nonce(stark_felt!(7_u8));
    let account_nonce = state.get_nonce_at(account_address).unwrap();
    let result = account_invoke_tx(
        invoke_tx_args! {nonce: invalid_nonce, ..pre_validation_base_args.clone()},
    )
    .execute(&mut state, &block_context, charge_fee, validate);
    assert_matches!(
        result.unwrap_err(),
        TransactionExecutionError::TransactionPreValidationError(
            TransactionPreValidationError::InvalidNonce {
                address, account_nonce: expected_nonce, incoming_tx_nonce
            }
        )
        if (address, expected_nonce, incoming_tx_nonce) ==
        (account_address, account_nonce, invalid_nonce)
    );

    // Second scenario: minimal fee not covered. Actual fee is precomputed.
    let (actual_gas_used, actual_fee) = gas_and_fee(6696, validate, &fee_type);
    let result = account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(10),
        resource_bounds: l1_resource_bounds(10, 10),
        nonce: nonce_manager.next(account_address),
        ..pre_validation_base_args.clone()
    })
    .execute(&mut state, &block_context, charge_fee, validate);
    if !charge_fee {
        check_gas_and_fee(&block_context, &result.unwrap(), actual_gas_used, actual_fee);
    } else {
        nonce_manager.rollback(account_address);
        if is_deprecated {
            assert_matches!(
                result.unwrap_err(),
                TransactionExecutionError::TransactionPreValidationError(
                    TransactionPreValidationError::TransactionFeeError(
                        TransactionFeeError::MaxFeeTooLow { .. }
                    )
                )
            );
        } else {
            assert_matches!(
                result.unwrap_err(),
                TransactionExecutionError::TransactionPreValidationError(
                    TransactionPreValidationError::TransactionFeeError(
                        TransactionFeeError::MaxL1GasAmountTooLow { .. }
                    )
                )
            );
        }
    }

    // Third scenario: resource bounds greater than balance.
    let result = account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(BALANCE + 1),
        resource_bounds: l1_resource_bounds((BALANCE / gas_price) as u64 + 10, gas_price),
        nonce: nonce_manager.next(account_address),
        ..pre_validation_base_args.clone()
    })
    .execute(&mut state, &block_context, charge_fee, validate);
    if !charge_fee {
        check_gas_and_fee(&block_context, &result.unwrap(), actual_gas_used, actual_fee);
    } else {
        nonce_manager.rollback(account_address);
        assert_matches!(
            result.unwrap_err(),
            TransactionExecutionError::TransactionPreValidationError(
                TransactionPreValidationError::TransactionFeeError(
                    TransactionFeeError::MaxFeeExceedsBalance { .. }
                )
            )
        );
    }

    // Fourth scenario: L1 gas price bound lower than the price on the block.
    if !is_deprecated {
        let result = account_invoke_tx(invoke_tx_args! {
            resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, gas_price - 1),
            nonce: nonce_manager.next(account_address),
            ..pre_validation_base_args.clone()
        })
        .execute(&mut state, &block_context, charge_fee, validate);
        if !charge_fee {
            check_gas_and_fee(&block_context, &result.unwrap(), actual_gas_used, actual_fee);
        } else {
            nonce_manager.rollback(account_address);
            assert_matches!(
                result.unwrap_err(),
                TransactionExecutionError::TransactionPreValidationError(
                    TransactionPreValidationError::TransactionFeeError(
                        TransactionFeeError::MaxL1GasPriceTooLow { .. }
                    )
                )
            );
        }
    }
}

/// Test simulate / validate / charge_fee flag combinations in (fallible) validation stage.
#[rstest]
#[case(TransactionVersion::ONE, FeeType::Eth)]
#[case(TransactionVersion::THREE, FeeType::Strk)]
fn test_simulate_validate_charge_fee_fail_validate(
    #[values(true, false)] only_query: bool,
    #[values(true, false)] validate: bool,
    #[values(true, false)] charge_fee: bool,
    #[case] version: TransactionVersion,
    #[case] fee_type: FeeType,
) {
    let block_context = BlockContext::create_for_account_testing();
    let max_fee = Fee(MAX_FEE);

    // Create a state with a contract that can fail validation on demand.
    let TestInitData { mut nonce_manager, block_context, .. } =
        create_test_init_data(max_fee, block_context);
    let mut falliable_state = create_state_with_falliable_validation_account();
    let falliable_sender_address = contract_address!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS);

    // Validation scenario: fallible validation.
    let (actual_gas_used, actual_fee) = gas_and_fee(31450, validate, &fee_type);
    let result = account_invoke_tx(invoke_tx_args! {
        max_fee,
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        signature: TransactionSignature(vec![
            StarkFelt::from(INVALID),
            StarkFelt::ZERO
        ]),
        sender_address: falliable_sender_address,
        calldata: calldata![
            stark_felt!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS), // Contract address.
            selector_from_name("foo").0,                       // EP selector.
            stark_felt!(0_u8)                                  // Calldata length.
        ],
        version,
        nonce: nonce_manager.next(falliable_sender_address),
        only_query,
    })
    .execute(&mut falliable_state, &block_context, charge_fee, validate);
    if !validate {
        // The reported fee should be the actual cost, regardless of whether or not fee is charged.
        check_gas_and_fee(&block_context, &result.unwrap(), actual_gas_used, actual_fee);
    } else {
        assert_matches!(
            result.unwrap_err(),
            TransactionExecutionError::ValidateTransactionError(
                EntryPointExecutionError::VirtualMachineExecutionErrorWithTrace { trace, .. }
            )
            if trace.contains("An ASSERT_EQ instruction failed: 1 != 0.")
        );
    }
}

/// Test simulate / validate / charge_fee flag combinations during execution.
#[rstest]
#[case(TransactionVersion::ONE, FeeType::Eth)]
#[case(TransactionVersion::THREE, FeeType::Strk)]
fn test_simulate_validate_charge_fee_mid_execution(
    #[values(true, false)] only_query: bool,
    #[values(true, false)] validate: bool,
    #[values(true, false)] charge_fee: bool,
    #[case] version: TransactionVersion,
    #[case] fee_type: FeeType,
) {
    let block_context = BlockContext::create_for_account_testing();
    let max_fee = Fee(MAX_FEE);
    let gas_price = block_context.gas_prices.get_by_fee_type(&fee_type);
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(max_fee, block_context);

    // If charge_fee is false, test that balance indeed doesn't change.
    let (current_balance, _) = state
        .get_fee_token_balance(&account_address, &block_context.fee_token_address(&fee_type))
        .unwrap();

    // Execution scenarios.
    // 1. Execution fails due to logic error.
    // 2. Execution fails due to out-of-resources error, due to max sender bounds, mid-run.
    // 3. Execution fails due to out-of-resources error, due to max block bounds, mid-run.
    let execution_base_args = invoke_tx_args! {
        max_fee: Fee(MAX_FEE),
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        sender_address: account_address,
        version,
        only_query,
    };

    // First scenario: logic error. Should result in revert; actual fee should be shown.
    let (revert_gas_used, revert_fee) = gas_and_fee(5987, validate, &fee_type);
    let tx_execution_info = account_invoke_tx(invoke_tx_args! {
        calldata: recurse_calldata(contract_address, true, 3),
        nonce: nonce_manager.next(account_address),
        ..execution_base_args.clone()
    })
    .execute(&mut state, &block_context, charge_fee, validate)
    .unwrap();
    assert!(tx_execution_info.is_reverted());
    check_gas_and_fee(&block_context, &tx_execution_info, revert_gas_used, revert_fee);
    let current_balance = check_balance(
        current_balance,
        &mut state,
        account_address,
        &block_context,
        &fee_type,
        charge_fee,
    );

    // Second scenario: limit resources via sender bounds. Should revert if and only if step limit
    // is derived from sender bounds (`charge_fee` mode).
    let (gas_bound, fee_bound) = gas_and_fee(5944, validate, &fee_type);
    // If `charge_fee` is true, execution is limited by sender bounds, so less resources will be
    // used. Otherwise, execution is limited by block bounds, so more resources will be used.
    let (limited_gas_used, limited_fee) = gas_and_fee(8392, validate, &fee_type);
    let (unlimited_gas_used, unlimited_fee) = gas_and_fee(10688, validate, &fee_type);
    let tx_execution_info = account_invoke_tx(invoke_tx_args! {
        max_fee: fee_bound,
        resource_bounds: l1_resource_bounds(gas_bound, gas_price),
        calldata: recurse_calldata(contract_address, false, 1000),
        nonce: nonce_manager.next(account_address),
        ..execution_base_args.clone()
    })
    .execute(&mut state, &block_context, charge_fee, validate)
    .unwrap();
    assert_eq!(tx_execution_info.is_reverted(), charge_fee);
    if charge_fee {
        assert!(tx_execution_info.revert_error.clone().unwrap().contains("no remaining steps"));
    }
    check_gas_and_fee(
        &block_context,
        &tx_execution_info,
        // In case `charge_fee = false` we completely ignore the sender bounds when executing the
        // transaction. If `charge_fee` is true, we limit the transaction steps according to the
        // sender bounds. However, there are other resources that consumes gas (e.g. L1 data
        // availability), hence the actual resources may exceed the senders bounds after all.
        if charge_fee { limited_gas_used } else { unlimited_gas_used },
        if charge_fee { fee_bound } else { unlimited_fee },
    );
    // Complete resources used are reported as actual_resources; but only the charged final fee is
    // shown in actual_fee.
    assert_eq!(
        calculate_tx_fee(&tx_execution_info.actual_resources, &block_context, &fee_type).unwrap(),
        if charge_fee { limited_fee } else { unlimited_fee }
    );
    let current_balance = check_balance(
        current_balance,
        &mut state,
        account_address,
        &block_context,
        &fee_type,
        charge_fee,
    );

    // Third scenario: only limit is block bounds. Expect resources consumed to be identical,
    // whether or not `charge_fee` is true.
    let mut low_step_block_context = block_context.clone();
    low_step_block_context.invoke_tx_max_n_steps = 10000;
    let (huge_gas_limit, huge_fee) = gas_and_fee(100000, validate, &fee_type);
    // Gas usage does not depend on `validate` flag in this scenario, because we reach the block
    // step limit during execution anyway. The actual limit when execution phase starts is slightly
    // lower when `validate` is true, but this is not reflected in the actual gas usage.
    let block_limit_gas = low_step_block_context.invoke_tx_max_n_steps as u64
        + 4 * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD as u64;
    let block_limit_fee =
        get_fee_by_l1_gas_usage(&block_context, block_limit_gas as u128, &fee_type);
    let tx_execution_info = account_invoke_tx(invoke_tx_args! {
        max_fee: huge_fee,
        resource_bounds: l1_resource_bounds(huge_gas_limit, gas_price),
        calldata: recurse_calldata(contract_address, false, 10000),
        nonce: nonce_manager.next(account_address),
        ..execution_base_args.clone()
    })
    .execute(&mut state, &low_step_block_context, charge_fee, validate)
    .unwrap();
    assert!(tx_execution_info.revert_error.clone().unwrap().contains("no remaining steps"));
    // Complete resources used are reported as actual_resources; but only the charged final fee is
    // shown in actual_fee. As a sanity check, verify that the fee derived directly from the
    // consumed resources is also equal to the expected fee.
    check_gas_and_fee(&block_context, &tx_execution_info, block_limit_gas, block_limit_fee);
    assert_eq!(
        calculate_tx_fee(&tx_execution_info.actual_resources, &low_step_block_context, &fee_type)
            .unwrap(),
        block_limit_fee
    );
    check_balance(
        current_balance,
        &mut state,
        account_address,
        &block_context,
        &fee_type,
        charge_fee,
    );
}

#[rstest]
#[case(TransactionVersion::ONE, FeeType::Eth)]
#[case(TransactionVersion::THREE, FeeType::Strk)]
fn test_simulate_validate_charge_fee_post_execution(
    #[values(true, false)] only_query: bool,
    #[values(true, false)] validate: bool,
    #[values(true, false)] charge_fee: bool,
    #[case] version: TransactionVersion,
    #[case] fee_type: FeeType,
) {
    let block_context = BlockContext::create_for_account_testing();
    let max_fee = Fee(MAX_FEE);
    let gas_price = block_context.gas_prices.get_by_fee_type(&fee_type);
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(max_fee, block_context);
    let fee_token_address = block_context.fee_token_address(&fee_type);

    // If charge_fee is false, test that balance indeed doesn't change.
    let (current_balance, _) =
        state.get_fee_token_balance(&account_address, &fee_token_address).unwrap();

    // Post-execution scenarios:
    // 1. Consumed too many resources (more than resource bounds).
    // 2. Balance is lower than actual fee.

    // First scenario: resource overdraft. Actual fee should be equal to sender bounds, actual gas
    // consumed should be equal to sender bounds + cost of nonce update.
    let (just_not_enough_gas_bound, just_not_enough_fee_bound) =
        gas_and_fee(6000, validate, &fee_type);
    let (unlimited_gas_used, unlimited_fee) = gas_and_fee(10688, validate, &fee_type);
    let reported_gas =
        just_not_enough_gas_bound + 4 * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD as u64;
    let tx_execution_info = account_invoke_tx(invoke_tx_args! {
        max_fee: just_not_enough_fee_bound,
        resource_bounds: l1_resource_bounds(just_not_enough_gas_bound, gas_price),
        calldata: recurse_calldata(contract_address, false, 1000),
        nonce: nonce_manager.next(account_address),
        sender_address: account_address,
        version,
        only_query,
    })
    .execute(&mut state, &block_context, charge_fee, validate)
    .unwrap();
    assert_eq!(tx_execution_info.is_reverted(), charge_fee);
    if charge_fee {
        assert!(tx_execution_info.revert_error.clone().unwrap().contains("no remaining steps"));
    }
    check_gas_and_fee(
        &block_context,
        &tx_execution_info,
        if charge_fee { reported_gas } else { unlimited_gas_used },
        if charge_fee { just_not_enough_fee_bound } else { unlimited_fee },
    );
    let current_balance = check_balance(
        current_balance,
        &mut state,
        account_address,
        &block_context,
        &fee_type,
        charge_fee,
    );

    // Second scenario: balance too low.
    // To test this scenario, we need to transfer funds out of the account (approve + transfer).

    // Approve the test contract to transfer funds.
    let recipient = stark_felt!(7_u8);
    let approve_calldata = create_calldata(
        fee_token_address,
        "approve",
        &[
            *contract_address.0.key(), // Calldata: to.
            stark_felt!(BALANCE),
            stark_felt!(0_u8),
        ],
    );
    let tx_execution_info = account_invoke_tx(invoke_tx_args! {
        max_fee,
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        calldata: approve_calldata,
        nonce: nonce_manager.next(account_address),
        sender_address: account_address,
        version,
        only_query,
    })
    .execute(&mut state, &block_context, charge_fee, validate)
    .unwrap();
    assert!(!tx_execution_info.is_reverted());
    let current_balance = check_balance(
        current_balance,
        &mut state,
        account_address,
        &block_context,
        &fee_type,
        charge_fee,
    );

    // Execute a transfer, and make sure we get the expected result.
    let (success_actual_gas, actual_fee) = gas_and_fee(13923, validate, &fee_type);
    let (fail_actual_gas, _) = gas_and_fee(6880, validate, &fee_type);
    assert!(stark_felt!(actual_fee) < current_balance);
    let transfer_amount = stark_felt_to_felt(current_balance) - Felt252::from(actual_fee.0 / 2);
    let transfer_calldata = create_calldata(
        contract_address,
        "test_write_and_transfer",
        &[
            stark_felt!(7_u8),                    // Calldata: storage address.
            stark_felt!(42_u8),                   // Calldata: storage value.
            recipient,                            // Calldata: to.
            felt_to_stark_felt(&transfer_amount), // Calldata: amount.
            *fee_token_address.0.key(),           // Calldata: fee token address.
        ],
    );
    let tx_execution_info = account_invoke_tx(invoke_tx_args! {
        max_fee: actual_fee,
        resource_bounds: l1_resource_bounds(success_actual_gas, gas_price),
        calldata: transfer_calldata,
        nonce: nonce_manager.next(account_address),
        sender_address: account_address,
        version,
        only_query,
    })
    .execute(&mut state, &block_context, charge_fee, validate)
    .unwrap();
    assert_eq!(tx_execution_info.is_reverted(), charge_fee);
    if charge_fee {
        assert!(
            tx_execution_info
                .revert_error
                .clone()
                .unwrap()
                .contains("Insufficient fee token balance.")
        );
    }
    check_gas_and_fee(
        &block_context,
        &tx_execution_info,
        // Since the failure was due to insufficient balance, the actual fee remains the same
        // regardless of whether or not the transaction was reverted.
        // The reported gas consumed, on the other hand, is much lower if the transaction was
        // reverted.
        if charge_fee { fail_actual_gas } else { success_actual_gas },
        actual_fee,
    );
    check_balance(
        current_balance,
        &mut state,
        account_address,
        &block_context,
        &fee_type,
        // Even if `charge_fee` is false, we expect balance to be reduced here; as in this case the
        // transaction will not be reverted, and the balance transfer should be applied.
        true,
    );
}
