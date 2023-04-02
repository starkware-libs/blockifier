use std::collections::HashMap;

use crate::block_context::BlockContext;
use crate::transaction::objects::ResourcesMapping;
use crate::abi::constants::N_STEPS_RESOURCE;
use crate::fee::fee_utils::calculate_l1_gas_by_cairo_usage;
use ::rstest::rstest;

// #[fixture]
// def general_config() -> StarknetGeneralConfig:
//     return StarknetGeneralConfig(
//         sequencer_address=1991,
//         starknet_os_config=StarknetOsConfig(fee_token_address=2022),
//         cairo_resource_fee_weights={
//             N_STEPS_RESOURCE: 1.0,
//             **{builtin: 1.0 for builtin in ALL_BUILTINS.except_for(KECCAK_BUILTIN).with_suffix()},
//         },
//     )

#[fixture]
fn cairo_resource_usage() -> &ResourcesMapping{
    let cairo_resource_usage = ResourcesMapping(HashMap::<String, usize>::new());
    cairo_resource_usage.0.insert(k, v)
}
    return {
        N_STEPS_RESOURCE: 1800,
        with_suffix(PEDERSEN_BUILTIN): 10,
        with_suffix(RANGE_CHECK_BUILTIN): 24,
        with_suffix(ECDSA_BUILTIN): 1,
        with_suffix(BITWISE_BUILTIN): 1,
        with_suffix(POSEIDON_BUILTIN): 1,
    }

#[rstest]
fn test_calculate_l1_gas_by_cairo_usage(
    block_context: &BlockContext, cairo_resource_usage: &ResourcesMapping){
    
    // Positive flow.
    // Verify calculation - in our case, n_steps is the heaviest resource.
    let l1_gas_by_cairo_usage = cairo_resource_usage.0.get(N_STEPS_RESOURCE);
    assert_eq!(l1_gas_by_cairo_usage, calculate_l1_gas_by_cairo_usage(
            block_context, cairo_resource_usage)
    );

    // Negative flow.
    // Pass dict with extra key.
    let invalid_cairo_resource_usage = ResourcesMapping(cairo_resource_usage.clone());
    invalid_cairo_resource_usage.0.insert(String::from("bad_resource_name"), 17);
    // The assertion below is similar to pytest.raises(..) in python.
    assert_eq!(
        std::panic::catch_unwind(||
            calculate_l1_gas_by_cairo_usage(block_context, &invalid_cairo_resource_usage);
        ).err().and_then(|a| a.downcast_ref::<String>().map(|s| {
            s == "Cairo resource names must be contained in fee weights dict."
        })),
        Some(true)
    );    
}
