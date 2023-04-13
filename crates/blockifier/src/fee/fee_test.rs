use std::collections::HashMap;

use assert_matches::assert_matches;

use crate::block_context::BlockContext;
use crate::fee::fee_utils::calculate_l1_gas_by_cairo_usage;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::ResourcesMapping;

fn get_block_context() -> BlockContext {
    let cairo_resource_fee_weights = HashMap::from([
        (String::from("n_steps"), 1_f64),
        (String::from("pedersen_builtin"), 1_f64),
        (String::from("range_check_builtin"), 1_f64),
        (String::from("ecdsa_builtin"), 1_f64),
        (String::from("bitwise_builtin"), 1_f64),
        (String::from("poseidon_builtin"), 1_f64),
        (String::from("output_builtin"), 1_f64),
        (String::from("ec_op_builtin"), 1_f64),
    ]);
    BlockContext { cairo_resource_fee_weights, ..BlockContext::create_for_testing() }
}

fn get_cairo_resource_usage() -> ResourcesMapping {
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
fn test_calculate_l1_gas_by_cairo_usage() {
    let block_context = get_block_context();
    let cairo_resource_usage = get_cairo_resource_usage();

    // Positive flow.
    // Verify calculation - in our case, n_steps is the heaviest resource.
    let l1_gas_by_cairo_usage = cairo_resource_usage.0.get("n_steps").unwrap();
    assert_eq!(
        *l1_gas_by_cairo_usage as f64,
        calculate_l1_gas_by_cairo_usage(&block_context, &cairo_resource_usage).unwrap()
    );

    // Negative flow.
    // Pass dict with extra key.
    let mut invalid_cairo_resource_usage = ResourcesMapping(cairo_resource_usage.0.clone());
    invalid_cairo_resource_usage.0.insert(String::from("bad_resource_name"), 17);
    let error =
        calculate_l1_gas_by_cairo_usage(&block_context, &invalid_cairo_resource_usage).unwrap_err();
    assert_matches!(error, TransactionExecutionError::CairoResourcesNotContainedInFeeWeights);
}
