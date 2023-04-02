use std::collections::HashMap;
use std::panic;

use rstest::{fixture, rstest};

use crate::block_context::BlockContext;
use crate::fee::fee_utils::calculate_l1_gas_by_cairo_usage;
use crate::transaction::objects::ResourcesMapping;

/// Use this function instead of panic::catch_unwind to achieve silence in output for
/// expected exceptions. For more information see here:
/// https://stackoverflow.com/questions/26469715
pub fn catch_unwind_silent<F: FnOnce() -> R + panic::UnwindSafe, R>(
    f: F,
) -> std::thread::Result<R> {
    let prev_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(f);
    panic::set_hook(prev_hook);
    result
}

#[fixture]
fn block_context() -> BlockContext {
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

#[fixture]
fn cairo_resource_usage() -> ResourcesMapping {
    let mut cairo_resource_usg = ResourcesMapping(HashMap::<String, usize>::new());
    cairo_resource_usg.0.insert(String::from("n_steps"), 1800);
    cairo_resource_usg.0.insert(String::from("pedersen_builtin"), 10);
    cairo_resource_usg.0.insert(String::from("range_check_builtin"), 24);
    cairo_resource_usg.0.insert(String::from("ecdsa_builtin"), 1);
    cairo_resource_usg.0.insert(String::from("bitwise_builtin"), 1);
    cairo_resource_usg.0.insert(String::from("poseidon_builtin"), 1);
    cairo_resource_usg
}

#[rstest]
fn test_calculate_l1_gas_by_cairo_usage(
    block_context: BlockContext,
    cairo_resource_usage: ResourcesMapping,
) {
    // Positive flow.
    // Verify calculation - in our case, n_steps is the heaviest resource.
    let l1_gas_by_cairo_usage = cairo_resource_usage
        .0
        .get("n_steps")
        .expect("cairo_resource_usage should have the key n_steps");
    assert_eq!(
        *l1_gas_by_cairo_usage,
        calculate_l1_gas_by_cairo_usage(&block_context, &cairo_resource_usage)
    );

    // Negative flow.
    // Pass dict with extra key.
    let mut invalid_cairo_resource_usage = ResourcesMapping(cairo_resource_usage.0.clone());
    invalid_cairo_resource_usage.0.insert(String::from("bad_resource_name"), 17);
    let expected_panic_msg = &"Cairo resource names must be contained in fee weights dict.";
    // Assert a panic with the message expected_panic_msg was raised.
    assert_eq!(
        catch_unwind_silent(|| {
            calculate_l1_gas_by_cairo_usage(&block_context, &invalid_cairo_resource_usage);
        })
        .err()
        .and_then(|a| a.downcast_ref::<&str>().map(|s| { s == expected_panic_msg })),
        Some(true),
        "Panic with expected message '{}' was not raised.",
        expected_panic_msg
    );
}
