use assert_matches::assert_matches;
use rstest::rstest;
use starknet_api::core::{ContractAddress, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{Calldata, Fee, TransactionSignature, TransactionVersion};
use starknet_api::{calldata, contract_address, patricia_key, stark_felt};

use crate::abi::abi_utils::selector_from_name;
use crate::block_context::BlockContext;
use crate::execution::errors::EntryPointExecutionError;
use crate::fee::fee_utils::{calculate_tx_l1_gas_usage, get_fee_by_l1_gas_usage};
use crate::invoke_tx_args;
use crate::state::cached_state::CachedState;
use crate::test_utils::{
    InvokeTxArgs, BALANCE, MAX_FEE, MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE,
    TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS,
};
use crate::transaction::errors::{
    TransactionExecutionError, TransactionFeeError, TransactionPreValidationError,
};
use crate::transaction::objects::FeeType;
use crate::transaction::test_utils::{
    account_invoke_tx, create_state, create_state_with_falliable_validation_account,
    create_test_init_data, l1_resource_bounds, TestInitData, INVALID,
};
use crate::transaction::transactions::ExecutableTransaction;

const VALIDATE_GAS_OVERHEAD: u64 = 21;

/// Returns the amount of L1 gas and derived fee, given base gas amount and a boolean indicating
/// if validation is to be done.
fn gas_and_fee(base_gas: u64, validate_mode: bool) -> (u64, Fee) {
    // Validation incurs a constant gas overhead.
    let gas = base_gas + if validate_mode { VALIDATE_GAS_OVERHEAD } else { 0 };
    (
        gas,
        get_fee_by_l1_gas_usage(
            &BlockContext::create_for_account_testing(),
            gas as u128,
            &FeeType::Eth,
        ),
    )
}

/// Test simulate / validate / charge_fee flag combinations in pre-validation stage.
#[rstest]
#[case(TransactionVersion::ONE, FeeType::Eth, true)]
#[case(TransactionVersion::THREE, FeeType::Strk, false)]
fn test_simulate_validate_charge_fee_pre_validate(
    #[values(true, false)] simulate: bool,
    #[values(true, false)] validate: bool,
    #[values(true, false)] charge_fee: bool,
    #[case] version: TransactionVersion,
    #[case] fee_type: FeeType,
    #[case] is_deprecated: bool,
) {
    let block_context = BlockContext::create_for_account_testing();
    let max_fee = Fee(MAX_FEE);
    let gas_price = block_context.gas_prices.get_by_fee_type(&fee_type);

    // Create two states, one of which contains a contract that can fail validation on demand.
    let TestInitData {
        state: mut initial_state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(max_fee, block_context.clone(), create_state(block_context.clone()));
    let mut state = CachedState::create_transactional(&mut initial_state);

    // In each scenario, need to verify the reported fee - even if charge_fee is false, we need to
    // report the fee.
    // Also, unwrap_err and if unwrap, verify revert state.

    // Pre-validation scenarios.
    // 1. Invalid nonce.
    // 2. Not enough resource bounds for minimal fee.
    // 3. Not enough balance for resource bounds.
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
        only_query: simulate,
    };

    // First scenario: invalid nonce. Regardless of flags, should fail.
    let invalid_nonce = Nonce(stark_felt!(7_u8));
    let account_nonce = nonce_manager.next(account_address);
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
    nonce_manager.rollback(account_address);

    // Second scenario: minimal fee not covered. Actual fee is precomputed.
    let (actual_gas_used, actual_fee) = gas_and_fee(6696, validate);
    let result = account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(10),
        resource_bounds: l1_resource_bounds(10, 10),
        nonce: nonce_manager.next(account_address),
        ..pre_validation_base_args.clone()
    })
    .execute(&mut state, &block_context, charge_fee, validate);
    if !charge_fee {
        let tx_execution_info = result.unwrap();
        assert_eq!(
            calculate_tx_l1_gas_usage(&tx_execution_info.actual_resources, &block_context).unwrap(),
            actual_gas_used as u128
        );
        assert_eq!(tx_execution_info.actual_fee, actual_fee);
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
        let tx_execution_info = result.unwrap();
        assert_eq!(
            calculate_tx_l1_gas_usage(&tx_execution_info.actual_resources, &block_context).unwrap(),
            actual_gas_used as u128
        );
        assert_eq!(tx_execution_info.actual_fee, actual_fee);
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
}

/// Test simulate / validate / charge_fee flag combinations in (fallible) validation stage.
#[rstest]
fn test_simulate_validate_charge_fee_fail_validate(
    #[values(true, false)] simulate: bool,
    #[values(true, false)] validate: bool,
    #[values(true, false)] charge_fee: bool,
    #[values(TransactionVersion::ONE, TransactionVersion::THREE)] version: TransactionVersion,
) {
    let block_context = BlockContext::create_for_account_testing();
    let max_fee = Fee(MAX_FEE);

    // Create two states, one of which contains a contract that can fail validation on demand.
    let TestInitData { mut nonce_manager, block_context, .. } =
        create_test_init_data(max_fee, block_context.clone(), create_state(block_context.clone()));
    let mut initial_falliable_state = create_state_with_falliable_validation_account();
    let mut falliable_state = CachedState::create_transactional(&mut initial_falliable_state);
    let falliable_sender_address = contract_address!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS);

    // Validation scenario: falliable validation.
    let (actual_gas_used, actual_fee) = gas_and_fee(31450, validate);
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
        only_query: simulate,
    })
    .execute(&mut falliable_state, &block_context, charge_fee, validate);
    if !validate {
        // The reported fee should be the actual cost, regardless of whether or not fee is charged.
        let tx_execution_info = result.unwrap();
        assert_eq!(
            calculate_tx_l1_gas_usage(&tx_execution_info.actual_resources, &block_context).unwrap(),
            actual_gas_used as u128
        );
        assert_eq!(tx_execution_info.actual_fee, actual_fee);
    } else {
        nonce_manager.rollback(falliable_sender_address);
        assert_matches!(
            result.unwrap_err(),
            TransactionExecutionError::ValidateTransactionError(
                EntryPointExecutionError::VirtualMachineExecutionErrorWithTrace { trace, .. }
            )
            if trace.contains("An ASSERT_EQ instruction failed: 1 != 0.")
        );
    }
}
