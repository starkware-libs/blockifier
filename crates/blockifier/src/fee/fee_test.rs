use std::collections::HashMap;

use assert_matches::assert_matches;

use crate::block_context::BlockContext;
use crate::fee::fee_utils::calculate_l1_gas_by_vm_usage;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::ResourcesMapping;

fn get_vm_resource_usage() -> ResourcesMapping {
    ResourcesMapping(HashMap::from([
        (String::from("n_steps"), 1800),
        (String::from("pedersen_builtin"), 10),
        (String::from("range_check_builtin"), 24),
        (String::from("ecdsa_builtin"), 1),
        (String::from("bitwise_builtin"), 1),
        (String::from("poseidon_builtin"), 1),
    ]))
}

#[test]
fn test_calculate_l1_gas_by_vm_usage() {
    let block_context = BlockContext::create_for_account_testing();
    let vm_resource_usage = get_vm_resource_usage();

    // Positive flow.
    // Verify calculation - in our case, n_steps is the heaviest resource.
    let l1_gas_by_vm_usage = vm_resource_usage.0.get("n_steps").unwrap();
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
