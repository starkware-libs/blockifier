use std::collections::HashMap;

use assert_matches::assert_matches;
use cairo_vm::vm::runners::builtin_runner::{
    BITWISE_BUILTIN_NAME, HASH_BUILTIN_NAME, POSEIDON_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME,
    SIGNATURE_BUILTIN_NAME,
};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use rstest::rstest;
use serde_json::de;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::abi::constants;
use crate::context::BlockContext;
use crate::fee::actual_cost::ActualCost;
use crate::fee::eth_gas_constants::DATA_GAS_PER_FIELD_ELEMENT;
use crate::fee::fee_checks::{FeeCheckError, FeeCheckReportFields, PostExecutionReport};
use crate::fee::fee_utils::calculate_l1_gas_by_vm_usage;
use crate::invoke_tx_args;
use crate::state::cached_state::StateChangesCount;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{CairoVersion, BALANCE};
use crate::transaction::errors::TransactionFeeError;
use crate::transaction::objects::{
    GasVector, ResourcesMapping, StarknetResources, TransactionResources,
};
use crate::transaction::test_utils::{account_invoke_tx, l1_resource_bounds};
use crate::utils::u128_from_usize;
use crate::versioned_constants::VersionedConstants;

fn get_tx_resources_from_gas_usages(l1_gas: usize, l1_data_gas: usize) -> TransactionResources {
    let vm_resources = ExecutionResources { n_steps: l1_gas, ..Default::default() };
    let state_changes_count = StateChangesCount {
        n_class_hash_updates: l1_data_gas / DATA_GAS_PER_FIELD_ELEMENT,
        ..StateChangesCount::default()
    };
    let starknet_resources =
        StarknetResources::new(0, 0, None, state_changes_count, None, std::iter::empty()).unwrap();
    TransactionResources { starknet_resources, vm_resources }
}

fn get_vm_resource_usage() -> ExecutionResources {
    ExecutionResources {
        n_steps: 1800,
        n_memory_holes: 0,
        builtin_instance_counter: HashMap::from([
            (HASH_BUILTIN_NAME.to_string(), 10),
            (RANGE_CHECK_BUILTIN_NAME.to_string(), 24),
            (SIGNATURE_BUILTIN_NAME.to_string(), 1),
            (BITWISE_BUILTIN_NAME.to_string(), 1),
            (POSEIDON_BUILTIN_NAME.to_string(), 1),
        ]),
    }
}

#[test]
fn test_calculate_l1_gas_by_vm_usage() {
    let versioned_constants = VersionedConstants::create_for_account_testing();
    let vm_resource_usage = get_vm_resource_usage();

    // Positive flow.
    // Verify calculation - in our case, n_steps is the heaviest resource.
    let l1_gas_by_vm_usage = vm_resource_usage.n_steps;
    assert_eq!(
        GasVector::from_l1_gas(u128_from_usize(l1_gas_by_vm_usage)),
        calculate_l1_gas_by_vm_usage(&versioned_constants, &vm_resource_usage).unwrap()
    );

    // Negative flow.
    // Pass dict with extra key.
    let mut invalid_vm_resource_usage = vm_resource_usage.clone();
    invalid_vm_resource_usage
        .builtin_instance_counter
        .insert(String::from("bad_resource_name"), 17);
    let error =
        calculate_l1_gas_by_vm_usage(&versioned_constants, &invalid_vm_resource_usage).unwrap_err();
    assert_matches!(error, TransactionFeeError::CairoResourcesNotContainedInFeeCosts);
}

/// Test the L1 gas limit bound, as applied to the case where both gas and data gas are consumed.
#[rstest]
#[case::no_dg_within_bounds(1000, 10, 10000, 0, 10000, false)]
#[case::no_dg_overdraft(1000, 10, 10001, 0, 10000, true)]
#[case::both_gases_within_bounds(1000, 10, 10000, 4992, 100000, false)]
#[case::both_gases_overdraft(1000, 10, 10000, 5024, 10000, true)]
// #[case::expensive_dg_no_dg_within_bounds(10, 1000, 10, 0, 10, false)]
// #[case::expensive_dg_with_dg_overdraft(10, 1000, 10, 1, 109, true)]
// #[case::expensive_dg_with_dg_within_bounds(10, 1000, 10, 1, 110, false)]
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
        version: TransactionVersion::THREE
    });

    let actual_resources = get_tx_resources_from_gas_usages(l1_gas_used, l1_data_gas_used);

    // This assertion ensures that the given gas parameters actually are the resources consumed by
    // the transaction.
    let use_kzg_da = l1_data_gas_used != 0;
    let expected_gas_vector = GasVector {
        l1_gas: u128_from_usize(l1_gas_used),
        l1_data_gas: u128_from_usize(l1_data_gas_used),
    };
    assert_eq!(
        expected_gas_vector,
        actual_resources.to_gas_vector(&block_context.versioned_constants, use_kzg_da,).unwrap()
    );

    let actual_cost = ActualCost { actual_fee: Fee(7), actual_resources, ..Default::default() };
    let charge_fee = true;
    let report = PostExecutionReport::new(
        &mut state,
        &block_context.to_tx_context(&tx),
        &actual_cost,
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
