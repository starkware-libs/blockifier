use std::collections::HashMap;

use assert_matches::assert_matches;
use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use rstest::rstest;
use starknet_api::transaction::Fee;

use crate::abi::constants::N_STEPS_RESOURCE;
use crate::context::BlockContext;
use crate::fee::actual_cost::TransactionReceipt;
use crate::fee::fee_checks::{FeeCheckError, FeeCheckReportFields, PostExecutionReport};
use crate::fee::fee_utils::calculate_l1_gas_by_vm_usage;
use crate::invoke_tx_args;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{CairoVersion, BALANCE};
use crate::transaction::objects::GasVector;
use crate::transaction::test_utils::{account_invoke_tx, l1_resource_bounds};
use crate::utils::u128_from_usize;
use crate::versioned_constants::VersionedConstants;

fn get_vm_resource_usage() -> ExecutionResources {
    ExecutionResources {
        n_steps: 10000,
        n_memory_holes: 0,
        builtin_instance_counter: HashMap::from([
            (BuiltinName::pedersen, 10),
            (BuiltinName::range_check, 24),
            (BuiltinName::ecdsa, 1),
            (BuiltinName::bitwise, 1),
            (BuiltinName::poseidon, 1),
        ]),
    }
}

#[test]
fn test_simple_calculate_l1_gas_by_vm_usage() {
    let versioned_constants = VersionedConstants::create_for_account_testing();
    let mut vm_resource_usage = get_vm_resource_usage();
    let n_reverted_steps = 15;

    // Positive flow.
    // Verify calculation - in our case, n_steps is the heaviest resource.
    let l1_gas_by_vm_usage =
        (*versioned_constants.vm_resource_fee_cost().get(N_STEPS_RESOURCE).unwrap()
            * (u128_from_usize(vm_resource_usage.n_steps + n_reverted_steps)))
        .ceil()
        .to_integer();
    assert_eq!(
        GasVector::from_l1_gas(l1_gas_by_vm_usage),
        calculate_l1_gas_by_vm_usage(&versioned_constants, &vm_resource_usage, n_reverted_steps)
            .unwrap()
    );

    // Another positive flow, this time the heaviest resource is range_check_builtin.
    let n_reverted_steps = 0;
    vm_resource_usage.n_steps =
        vm_resource_usage.builtin_instance_counter.get(&BuiltinName::range_check).unwrap() - 1;
    let l1_gas_by_vm_usage =
        vm_resource_usage.builtin_instance_counter.get(&BuiltinName::range_check).unwrap();
    assert_eq!(
        GasVector::from_l1_gas(u128_from_usize(*l1_gas_by_vm_usage)),
        calculate_l1_gas_by_vm_usage(&versioned_constants, &vm_resource_usage, n_reverted_steps)
            .unwrap()
    );
}

#[test]
fn test_float_calculate_l1_gas_by_vm_usage() {
    let versioned_constants = VersionedConstants::create_float_for_testing();
    let mut vm_resource_usage = get_vm_resource_usage();

    // Positive flow.
    // Verify calculation - in our case, n_steps is the heaviest resource.
    let n_reverted_steps = 300;
    let l1_gas_by_vm_usage =
        ((*versioned_constants.vm_resource_fee_cost().get(N_STEPS_RESOURCE).unwrap())
            * u128_from_usize(vm_resource_usage.n_steps + n_reverted_steps))
        .ceil()
        .to_integer();
    assert_eq!(
        GasVector::from_l1_gas(l1_gas_by_vm_usage),
        calculate_l1_gas_by_vm_usage(&versioned_constants, &vm_resource_usage, n_reverted_steps)
            .unwrap()
    );

    // Another positive flow, this time the heaviest resource is ecdsa_builtin.
    vm_resource_usage.n_steps = 200;
    let l1_gas_by_vm_usage = ((*versioned_constants
        .vm_resource_fee_cost()
        .get(BuiltinName::ecdsa.to_str_with_suffix())
        .unwrap())
        * u128_from_usize(
            *vm_resource_usage.builtin_instance_counter.get(&BuiltinName::ecdsa).unwrap(),
        ))
    .ceil()
    .to_integer();

    assert_eq!(
        GasVector::from_l1_gas(l1_gas_by_vm_usage),
        calculate_l1_gas_by_vm_usage(&versioned_constants, &vm_resource_usage, n_reverted_steps)
            .unwrap()
    );
}

/// Test the L1 gas limit bound, as applied to the case where both gas and data gas are consumed.
#[rstest]
#[case::no_dg_within_bounds(1000, 10, 10000, 0, 10000, false)]
#[case::no_dg_overdraft(1000, 10, 10001, 0, 10000, true)]
#[case::both_gases_within_bounds(1000, 10, 10000, 5000, 100000, false)]
#[case::both_gases_overdraft(1000, 10, 10000, 5000, 10000, true)]
#[case::expensive_dg_no_dg_within_bounds(10, 1000, 10, 0, 10, false)]
#[case::expensive_dg_with_dg_overdraft(10, 1000, 10, 1, 109, true)]
#[case::expensive_dg_with_dg_within_bounds(10, 1000, 10, 1, 110, false)]
fn test_discounted_gas_overdraft(
    #[case] gas_price: u128,
    #[case] data_gas_price: u128,
    #[case] l1_gas_used: usize,
    #[case] l1_data_gas_used: usize,
    #[case] gas_bound: u64,
    #[case] expect_failure: bool,
) {
    let mut block_context = BlockContext::create_for_account_testing();
    block_context.block_info.gas_prices.strk_l1_gas_price = gas_price.try_into().unwrap();
    block_context.block_info.gas_prices.strk_l1_data_gas_price = data_gas_price.try_into().unwrap();

    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo0);
    let mut state = test_state(&block_context.chain_info, BALANCE, &[(account, 1)]);
    let tx = account_invoke_tx(invoke_tx_args! {
        sender_address: account.get_instance_address(0),
        resource_bounds: l1_resource_bounds(gas_bound, gas_price * 10),
    });

    let tx_receipt = TransactionReceipt {
        fee: Fee(7),
        gas: GasVector {
            l1_gas: u128_from_usize(l1_gas_used),
            l1_data_gas: u128_from_usize(l1_data_gas_used),
        },
        ..Default::default()
    };
    let charge_fee = true;
    let report = PostExecutionReport::new(
        &mut state,
        &block_context.to_tx_context(&tx),
        &tx_receipt,
        charge_fee,
    )
    .unwrap();

    if expect_failure {
        let error = report.error().unwrap();
        let expected_actual_amount = u128_from_usize(l1_gas_used)
            + (u128_from_usize(l1_data_gas_used) * data_gas_price) / gas_price;
        assert_matches!(
            error, FeeCheckError::MaxL1GasAmountExceeded { max_amount, actual_amount }
            if max_amount == u128::from(gas_bound) && actual_amount == expected_actual_amount
        )
    } else {
        assert_matches!(report.error(), None);
    }
}
