use assert_matches::assert_matches;
use cairo_felt::Felt252;
use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Calldata, Fee, TransactionSignature, TransactionVersion};

use crate::context::{BlockContext, ChainInfo};
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::execution::syscalls::SyscallSelector;
use crate::fee::fee_utils::{calculate_tx_fee, get_fee_by_gas_vector};
use crate::state::cached_state::CachedState;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{
    create_calldata, create_trivial_calldata, get_syscall_resources, get_tx_resources,
    u64_from_usize, CairoVersion, NonceManager, BALANCE, MAX_FEE, MAX_L1_GAS_AMOUNT,
    MAX_L1_GAS_PRICE,
};
use crate::transaction::errors::{
    TransactionExecutionError, TransactionFeeError, TransactionPreValidationError,
};
use crate::transaction::objects::{FeeType, GasVector, TransactionExecutionInfo};
use crate::transaction::test_utils::{account_invoke_tx, l1_resource_bounds, INVALID};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transactions::ExecutableTransaction;
use crate::{invoke_tx_args, nonce};
const VALIDATE_GAS_OVERHEAD: u64 = 21;

struct FlavorTestInitialState {
    pub state: CachedState<DictStateReader>,
    pub account_address: ContractAddress,
    pub faulty_account_address: ContractAddress,
    pub test_contract_address: ContractAddress,
    pub nonce_manager: NonceManager,
}

fn create_flavors_test_state(
    chain_info: &ChainInfo,
    cairo_version: CairoVersion,
) -> FlavorTestInitialState {
    let test_contract = FeatureContract::TestContract(cairo_version);
    let account_contract = FeatureContract::AccountWithoutValidations(cairo_version);
    let faulty_account_contract = FeatureContract::FaultyAccount(cairo_version);
    let state = test_state(
        chain_info,
        BALANCE,
        &[(account_contract, 1), (faulty_account_contract, 1), (test_contract, 1)],
    );
    FlavorTestInitialState {
        state,
        account_address: account_contract.get_instance_address(0),
        faulty_account_address: faulty_account_contract.get_instance_address(0),
        test_contract_address: test_contract.get_instance_address(0),
        nonce_manager: NonceManager::default(),
    }
}

/// Checks that balance of the account decreased if and only if `charge_fee` is true.
/// Returns the new balance.
fn check_balance<S: StateReader>(
    current_balance: StarkFelt,
    state: &mut CachedState<S>,
    account_address: ContractAddress,
    chain_info: &ChainInfo,
    fee_type: &FeeType,
    charge_fee: bool,
) -> StarkFelt {
    let (new_balance, _) = state
        .get_fee_token_balance(account_address, chain_info.fee_token_address(fee_type))
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
        get_fee_by_gas_vector(
            &BlockContext::create_for_account_testing().block_info,
            GasVector::from_l1_gas(gas.into()),
            fee_type,
        ),
    )
}

/// Asserts gas used and reported fee are as expected.
// TODO(Aner, 21/01/24) modify for 4844 (taking blob_gas into account).
fn check_gas_and_fee(
    block_context: &BlockContext,
    tx_execution_info: &TransactionExecutionInfo,
    fee_type: &FeeType,
    expected_actual_gas: u64,
    expected_actual_fee: Fee,
    expected_cost_of_resources: Fee,
) {
    assert_eq!(
        tx_execution_info
            .actual_resources
            .to_gas_vector(&block_context.versioned_constants, block_context.block_info.use_kzg_da)
            .unwrap()
            .l1_gas,
        expected_actual_gas.into()
    );

    assert_eq!(tx_execution_info.actual_fee, expected_actual_fee);
    // Future compatibility: resources other than the L1 gas usage may affect the fee (currently,
    // `calculate_tx_fee` is simply the result of `calculate_tx_gas_usage_vector` times gas price).
    assert_eq!(
        calculate_tx_fee(&tx_execution_info.actual_resources, block_context, fee_type).unwrap(),
        expected_cost_of_resources
    );
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
    // TODO(Dori, 1/1/2024): Add Cairo1 case, after price abstraction is implemented.
    #[values(CairoVersion::Cairo0)] cairo_version: CairoVersion,
    #[case] version: TransactionVersion,
    #[case] fee_type: FeeType,
    #[case] is_deprecated: bool,
) {
    let block_context = BlockContext::create_for_account_testing();
    let max_fee = Fee(MAX_FEE);
    let gas_price = block_context.block_info.gas_prices.get_gas_price_by_fee_type(&fee_type);
    let FlavorTestInitialState {
        mut state,
        account_address,
        test_contract_address,
        mut nonce_manager,
        ..
    } = create_flavors_test_state(&block_context.chain_info, cairo_version);

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
        calldata: create_trivial_calldata(test_contract_address),
        version,
        only_query,
    };

    // First scenario: invalid nonce. Regardless of flags, should fail.
    let invalid_nonce = nonce!(7_u8);
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
    let (actual_gas_used, actual_fee) = gas_and_fee(
        u64_from_usize(
            get_syscall_resources(SyscallSelector::CallContract).n_steps
                + get_tx_resources(TransactionType::InvokeFunction).n_steps
                + 1738,
        ),
        validate,
        &fee_type,
    );
    let result = account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(10),
        resource_bounds: l1_resource_bounds(10, 10),
        nonce: nonce_manager.next(account_address),
        ..pre_validation_base_args.clone()
    })
    .execute(&mut state, &block_context, charge_fee, validate);
    if !charge_fee {
        check_gas_and_fee(
            &block_context,
            &result.unwrap(),
            &fee_type,
            actual_gas_used,
            actual_fee,
            actual_fee,
        );
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

    // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion works.
    let balance_over_gas_price: u64 =
        (BALANCE / gas_price).try_into().expect("Failed to convert u128 to u64.");
    let result = account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(BALANCE + 1),
        resource_bounds: l1_resource_bounds(balance_over_gas_price + 10, gas_price.into()),
        nonce: nonce_manager.next(account_address),
        ..pre_validation_base_args.clone()
    })
    .execute(&mut state, &block_context, charge_fee, validate);
    if !charge_fee {
        check_gas_and_fee(
            &block_context,
            &result.unwrap(),
            &fee_type,
            actual_gas_used,
            actual_fee,
            actual_fee,
        );
    } else {
        nonce_manager.rollback(account_address);
        if is_deprecated {
            assert_matches!(
                result.unwrap_err(),
                TransactionExecutionError::TransactionPreValidationError(
                    TransactionPreValidationError::TransactionFeeError(
                        TransactionFeeError::MaxFeeExceedsBalance { .. }
                    )
                )
            );
        } else {
            assert_matches!(
                result.unwrap_err(),
                TransactionExecutionError::TransactionPreValidationError(
                    TransactionPreValidationError::TransactionFeeError(
                        TransactionFeeError::L1GasBoundsExceedBalance { .. }
                    )
                )
            );
        }
    }

    // Fourth scenario: L1 gas price bound lower than the price on the block.
    if !is_deprecated {
        let result = account_invoke_tx(invoke_tx_args! {
            resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, u128::from(gas_price) - 1),
            nonce: nonce_manager.next(account_address),
            ..pre_validation_base_args
        })
        .execute(&mut state, &block_context, charge_fee, validate);
        if !charge_fee {
            check_gas_and_fee(
                &block_context,
                &result.unwrap(),
                &fee_type,
                actual_gas_used,
                actual_fee,
                actual_fee,
            );
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
    // TODO(Dori, 1/1/2024): Add Cairo1 case, after price abstraction is implemented.
    #[values(CairoVersion::Cairo0)] cairo_version: CairoVersion,
    #[case] version: TransactionVersion,
    #[case] fee_type: FeeType,
) {
    let block_context = BlockContext::create_for_account_testing();
    let max_fee = Fee(MAX_FEE);

    // Create a state with a contract that can fail validation on demand.
    let FlavorTestInitialState {
        state: mut falliable_state,
        faulty_account_address,
        mut nonce_manager,
        ..
    } = create_flavors_test_state(&block_context.chain_info, cairo_version);

    // Validation scenario: fallible validation.
    let (actual_gas_used, actual_fee) = gas_and_fee(
        u64_from_usize(get_tx_resources(TransactionType::InvokeFunction).n_steps + 27229),
        validate,
        &fee_type,
    );
    let result = account_invoke_tx(invoke_tx_args! {
        max_fee,
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        signature: TransactionSignature(vec![
            StarkFelt::from(INVALID),
            StarkFelt::ZERO
        ]),
        sender_address: faulty_account_address,
        calldata: create_calldata(faulty_account_address, "foo", &[]),
        version,
        nonce: nonce_manager.next(faulty_account_address),
        only_query,
    })
    .execute(&mut falliable_state, &block_context, charge_fee, validate);
    if !validate {
        // The reported fee should be the actual cost, regardless of whether or not fee is charged.
        check_gas_and_fee(
            &block_context,
            &result.unwrap(),
            &fee_type,
            actual_gas_used,
            actual_fee,
            actual_fee,
        );
    } else {
        assert!(
            result.unwrap_err().to_string().contains("An ASSERT_EQ instruction failed: 1 != 0.")
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
    // TODO(Dori, 1/1/2024): Add Cairo1 case, after price abstraction is implemented.
    #[values(CairoVersion::Cairo0)] cairo_version: CairoVersion,
    #[case] version: TransactionVersion,
    #[case] fee_type: FeeType,
) {
    let block_context = BlockContext::create_for_account_testing();
    let chain_info = &block_context.chain_info;
    let gas_price = block_context.block_info.gas_prices.get_gas_price_by_fee_type(&fee_type);
    let FlavorTestInitialState {
        mut state,
        account_address,
        test_contract_address,
        mut nonce_manager,
        ..
    } = create_flavors_test_state(chain_info, cairo_version);

    // If charge_fee is false, test that balance indeed doesn't change.
    let (current_balance, _) = state
        .get_fee_token_balance(account_address, chain_info.fee_token_address(&fee_type))
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
    let (revert_gas_used, revert_fee) = gas_and_fee(
        u64_from_usize(get_tx_resources(TransactionType::InvokeFunction).n_steps + 1719),
        validate,
        &fee_type,
    );
    let tx_execution_info = account_invoke_tx(invoke_tx_args! {
        calldata: recurse_calldata(test_contract_address, true, 3),
        nonce: nonce_manager.next(account_address),
        ..execution_base_args.clone()
    })
    .execute(&mut state, &block_context, charge_fee, validate)
    .unwrap();
    assert!(tx_execution_info.is_reverted());
    check_gas_and_fee(
        &block_context,
        &tx_execution_info,
        &fee_type,
        revert_gas_used,
        revert_fee,
        revert_fee,
    );
    let current_balance = check_balance(
        current_balance,
        &mut state,
        account_address,
        &block_context.chain_info,
        &fee_type,
        charge_fee,
    );

    // Second scenario: limit resources via sender bounds. Should revert if and only if step limit
    // is derived from sender bounds (`charge_fee` mode).
    let (gas_bound, fee_bound) = gas_and_fee(6001, validate, &fee_type);
    // If `charge_fee` is true, execution is limited by sender bounds, so less resources will be
    // used. Otherwise, execution is limited by block bounds, so more resources will be used.
    let (limited_gas_used, limited_fee) = gas_and_fee(7653, validate, &fee_type);
    let (unlimited_gas_used, unlimited_fee) = gas_and_fee(
        u64_from_usize(
            get_syscall_resources(SyscallSelector::CallContract).n_steps
                + get_tx_resources(TransactionType::InvokeFunction).n_steps
                + 5730,
        ),
        validate,
        &fee_type,
    );
    let tx_execution_info = account_invoke_tx(invoke_tx_args! {
        max_fee: fee_bound,
        resource_bounds: l1_resource_bounds(gas_bound, gas_price.into()),
        calldata: recurse_calldata(test_contract_address, false, 1000),
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
        &fee_type,
        // In case `charge_fee = false` we completely ignore the sender bounds when executing the
        // transaction. If `charge_fee` is true, we limit the transaction steps according to the
        // sender bounds. However, there are other resources that consumes gas (e.g. L1 data
        // availability), hence the actual resources may exceed the senders bounds after all.
        if charge_fee { limited_gas_used } else { unlimited_gas_used },
        if charge_fee { fee_bound } else { unlimited_fee },
        // Complete resources used are reported as actual_resources; but only the charged final fee
        // is shown in actual_fee.
        if charge_fee { limited_fee } else { unlimited_fee },
    );
    let current_balance = check_balance(
        current_balance,
        &mut state,
        account_address,
        chain_info,
        &fee_type,
        charge_fee,
    );

    // Third scenario: only limit is block bounds. Expect resources consumed to be identical,
    // whether or not `charge_fee` is true.
    let mut low_step_block_context = block_context.clone();
    low_step_block_context.versioned_constants.invoke_tx_max_n_steps = 10000;
    let (huge_gas_limit, huge_fee) = gas_and_fee(100000, validate, &fee_type);
    // Gas usage does not depend on `validate` flag in this scenario, because we reach the block
    // step limit during execution anyway. The actual limit when execution phase starts is slightly
    // lower when `validate` is true, but this is not reflected in the actual gas usage.
    let invoke_tx_max_n_steps_as_u64: u64 =
        low_step_block_context.versioned_constants.invoke_tx_max_n_steps.into();
    let block_limit_gas = invoke_tx_max_n_steps_as_u64 + 1652;
    let block_limit_fee = get_fee_by_gas_vector(
        &block_context.block_info,
        GasVector::from_l1_gas(block_limit_gas.into()),
        &fee_type,
    );
    let tx_execution_info = account_invoke_tx(invoke_tx_args! {
        max_fee: huge_fee,
        resource_bounds: l1_resource_bounds(huge_gas_limit, gas_price.into()),
        calldata: recurse_calldata(test_contract_address, false, 10000),
        nonce: nonce_manager.next(account_address),
        ..execution_base_args
    })
    .execute(&mut state, &low_step_block_context, charge_fee, validate)
    .unwrap();
    assert!(tx_execution_info.revert_error.clone().unwrap().contains("no remaining steps"));
    // Complete resources used are reported as actual_resources; but only the charged final fee is
    // shown in actual_fee. As a sanity check, verify that the fee derived directly from the
    // consumed resources is also equal to the expected fee.
    check_gas_and_fee(
        &block_context,
        &tx_execution_info,
        &fee_type,
        block_limit_gas,
        block_limit_fee,
        block_limit_fee,
    );
    check_balance(current_balance, &mut state, account_address, chain_info, &fee_type, charge_fee);
}

#[rstest]
#[case(TransactionVersion::ONE, FeeType::Eth, true)]
#[case(TransactionVersion::THREE, FeeType::Strk, false)]
fn test_simulate_validate_charge_fee_post_execution(
    #[values(true, false)] only_query: bool,
    #[values(true, false)] validate: bool,
    #[values(true, false)] charge_fee: bool,
    // TODO(Dori, 1/1/2024): Add Cairo1 case, after price abstraction is implemented.
    #[values(CairoVersion::Cairo0)] cairo_version: CairoVersion,
    #[case] version: TransactionVersion,
    #[case] fee_type: FeeType,
    #[case] is_deprecated: bool,
) {
    let block_context = BlockContext::create_for_account_testing();
    let gas_price = block_context.block_info.gas_prices.get_gas_price_by_fee_type(&fee_type);
    let chain_info = &block_context.chain_info;
    let fee_token_address = chain_info.fee_token_address(&fee_type);

    let FlavorTestInitialState {
        mut state,
        account_address,
        test_contract_address,
        mut nonce_manager,
        ..
    } = create_flavors_test_state(chain_info, cairo_version);

    // If charge_fee is false, test that balance indeed doesn't change.
    let (current_balance, _) =
        state.get_fee_token_balance(account_address, fee_token_address).unwrap();

    // Post-execution scenarios:
    // 1. Consumed too many resources (more than resource bounds).
    // 2. Balance is lower than actual fee.

    // First scenario: resource overdraft.
    // If `charge_fee` is false - we do not revert, and simply report the fee and resources as used.
    // If `charge_fee` is true, we revert, charge the maximal allowed fee (derived from sender
    // bounds), and report resources base on execution steps reverted + other overhead.
    let base_gas_bound = 8000;
    let (just_not_enough_gas_bound, just_not_enough_fee_bound) =
        gas_and_fee(base_gas_bound, validate, &fee_type);
    // `__validate__` and overhead resources + number of reverted steps, comes out slightly more
    // than the gas bound.
    let (revert_gas_usage, revert_fee) = gas_and_fee(
        u64_from_usize(get_tx_resources(TransactionType::InvokeFunction).n_steps) + 5730,
        validate,
        &fee_type,
    );
    let (unlimited_gas_used, unlimited_fee) = gas_and_fee(
        u64_from_usize(
            get_syscall_resources(SyscallSelector::CallContract).n_steps
                + get_tx_resources(TransactionType::InvokeFunction).n_steps
                + 5730,
        ),
        validate,
        &fee_type,
    );
    let tx_execution_info = account_invoke_tx(invoke_tx_args! {
        max_fee: just_not_enough_fee_bound,
        resource_bounds: l1_resource_bounds(just_not_enough_gas_bound, gas_price.into()),
        calldata: recurse_calldata(test_contract_address, false, 1000),
        nonce: nonce_manager.next(account_address),
        sender_address: account_address,
        version,
        only_query,
    })
    .execute(&mut state, &block_context, charge_fee, validate)
    .unwrap();
    assert_eq!(tx_execution_info.is_reverted(), charge_fee);
    if charge_fee {
        assert!(tx_execution_info.revert_error.clone().unwrap().starts_with(if is_deprecated {
            "Insufficient max fee"
        } else {
            "Insufficient max L1 gas"
        }));
    }

    check_gas_and_fee(
        &block_context,
        &tx_execution_info,
        &fee_type,
        if charge_fee { revert_gas_usage } else { unlimited_gas_used },
        if charge_fee { just_not_enough_fee_bound } else { unlimited_fee },
        if charge_fee { revert_fee } else { unlimited_fee },
    );
    let current_balance = check_balance(
        current_balance,
        &mut state,
        account_address,
        chain_info,
        &fee_type,
        charge_fee,
    );

    // Second scenario: balance too low.
    // Execute a transfer, and make sure we get the expected result.
    let (success_actual_gas, actual_fee) = gas_and_fee(
        u64_from_usize(
            get_syscall_resources(SyscallSelector::CallContract).n_steps
                + get_tx_resources(TransactionType::InvokeFunction).n_steps
                + 4244,
        ),
        validate,
        &fee_type,
    );
    let (fail_actual_gas, fail_actual_fee) = gas_and_fee(
        u64_from_usize(get_tx_resources(TransactionType::InvokeFunction).n_steps + 2252),
        validate,
        &fee_type,
    );
    assert!(stark_felt!(actual_fee) < current_balance);
    let transfer_amount = stark_felt_to_felt(current_balance) - Felt252::from(actual_fee.0 / 2);
    let recipient = stark_felt!(7_u8);
    let transfer_calldata = create_calldata(
        fee_token_address,
        "transfer",
        &[
            recipient, // Calldata: to.
            felt_to_stark_felt(&transfer_amount),
            stark_felt!(0_u8),
        ],
    );
    let tx_execution_info = account_invoke_tx(invoke_tx_args! {
        max_fee: actual_fee,
        resource_bounds: l1_resource_bounds(success_actual_gas, gas_price.into()),
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
        &fee_type,
        // Since the failure was due to insufficient balance, the actual fee remains the same
        // regardless of whether or not the transaction was reverted.
        // The reported gas consumed, on the other hand, is much lower if the transaction was
        // reverted.
        if charge_fee { fail_actual_gas } else { success_actual_gas },
        actual_fee,
        if charge_fee { fail_actual_fee } else { actual_fee },
    );
    check_balance(
        current_balance,
        &mut state,
        account_address,
        chain_info,
        &fee_type,
        // Even if `charge_fee` is false, we expect balance to be reduced here; as in this case the
        // transaction will not be reverted, and the balance transfer should be applied.
        true,
    );
}
