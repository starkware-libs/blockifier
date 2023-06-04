use std::collections::HashMap;

use assert_matches::assert_matches;
use cairo_vm::vm::runners::builtin_runner::{
    BITWISE_BUILTIN_NAME, HASH_BUILTIN_NAME, POSEIDON_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME,
    SIGNATURE_BUILTIN_NAME,
};

use crate::abi::constants::N_STEPS_RESOURCE;
use crate::block_context::BlockContext;
use crate::fee::fee_utils::calculate_l1_gas_by_vm_usage;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::ResourcesMapping;

fn get_vm_resource_usage() -> ResourcesMapping {
    ResourcesMapping(HashMap::from([
        (String::from(N_STEPS_RESOURCE), 1800),
        (String::from(HASH_BUILTIN_NAME), 10),
        (String::from(RANGE_CHECK_BUILTIN_NAME), 24),
        (String::from(SIGNATURE_BUILTIN_NAME), 1),
        (String::from(BITWISE_BUILTIN_NAME), 1),
        (String::from(POSEIDON_BUILTIN_NAME), 1),
    ]))
}

#[test]
fn test_calculate_l1_gas_by_vm_usage() {
    let block_context = BlockContext::create_for_account_testing();
    let vm_resource_usage = get_vm_resource_usage();

    // Positive flow.
    // Verify calculation - in our case, n_steps is the heaviest resource.
    let l1_gas_by_vm_usage = vm_resource_usage.0.get(N_STEPS_RESOURCE).unwrap();
    assert_eq!(
        *l1_gas_by_vm_usage as f64,
        calculate_l1_gas_by_vm_usage(&block_context, &vm_resource_usage).unwrap()
    );

    // Negative flow.
    // Pass dict with extra key.
    let mut invalid_vm_resource_usage = ResourcesMapping(vm_resource_usage.0.clone());
    invalid_vm_resource_usage.0.insert(String::from("bad_resource_name"), 17);
    let error =
        calculate_l1_gas_by_vm_usage(&block_context, &invalid_vm_resource_usage).unwrap_err();
    assert_matches!(error, TransactionExecutionError::CairoResourcesNotContainedInFeeCosts);
}
