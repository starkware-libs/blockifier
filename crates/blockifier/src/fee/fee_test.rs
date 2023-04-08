use std::collections::HashMap;

use crate::block_context::BlockContext;
use crate::fee::fee_utils::calculate_l1_gas_by_cairo_usage;
use crate::transaction::objects::ResourcesMapping;

fn get_block_context() -> BlockContext {
    let mut block_context = BlockContext::create_for_testing();
    let mut cairo_resource_fee_weights = HashMap::<String, u32>::new();
    cairo_resource_fee_weights.insert(String::from("n_steps"), 1);
    cairo_resource_fee_weights.insert(String::from("pedersen_builtin"), 1);
    cairo_resource_fee_weights.insert(String::from("range_check_builtin"), 1);
    cairo_resource_fee_weights.insert(String::from("ecdsa_builtin"), 1);
    cairo_resource_fee_weights.insert(String::from("bitwise_builtin"), 1);
    cairo_resource_fee_weights.insert(String::from("poseidon_builtin"), 1);
    cairo_resource_fee_weights.insert(String::from("output_builtin"), 1);
    cairo_resource_fee_weights.insert(String::from("ec_op_builtin"), 1);
    block_context.cairo_resource_fee_weights = cairo_resource_fee_weights;
    block_context
}

fn get_cairo_resource_usage() -> ResourcesMapping {
    let mut cairo_resource_usg = ResourcesMapping(HashMap::<String, usize>::new());
    cairo_resource_usg.0.insert(String::from("n_steps"), 1800);
    cairo_resource_usg.0.insert(String::from("pedersen_builtin"), 10);
    cairo_resource_usg.0.insert(String::from("range_check_builtin"), 24);
    cairo_resource_usg.0.insert(String::from("ecdsa_builtin"), 1);
    cairo_resource_usg.0.insert(String::from("bitwise_builtin"), 1);
    cairo_resource_usg.0.insert(String::from("poseidon_builtin"), 1);
    cairo_resource_usg
}

#[test]
fn test_calculate_l1_gas_by_cairo_usage() {
    let block_context = get_block_context();
    let cairo_resource_usage = get_cairo_resource_usage();

    // Positive flow.
    // Verify calculation - in our case, n_steps is the heaviest resource.
    let l1_gas_by_cairo_usage = cairo_resource_usage
        .0
        .get("n_steps")
        .expect("cairo_resource_usage should have the key n_steps");
    assert_eq!(
        *l1_gas_by_cairo_usage as u128,
        calculate_l1_gas_by_cairo_usage(&block_context, &cairo_resource_usage)
            .expect("calculate_l1_gas_by_cairo_usage returned error on valid input.")
    );

    // Negative flow.
    // Pass dict with extra key.
    let mut invalid_cairo_resource_usage = ResourcesMapping(cairo_resource_usage.0.clone());
    invalid_cairo_resource_usage.0.insert(String::from("bad_resource_name"), 17);
    let expected_err_msg = "Cairo resource names must be contained in fee weights dict.";
    let error = calculate_l1_gas_by_cairo_usage(&block_context, &invalid_cairo_resource_usage)
        .expect_err(
            "Expected TransactionExecutionError::CairoResourcesNotContainedInFeeWeights, 
    got Ok instead.",
        )
        .to_string();
    if !(error == expected_err_msg.to_string()) {
        panic!("Expected error: {expected_err_msg}.\nGot: {error}")
    }
}
