use crate::block_context::BlockContext;
use crate::transaction::objects::ResourcesMapping;
use crate::abi::constants::N_STEPS_RESOURCE;
use crate::fee::fee_utils::calculate_l1_gas_by_cairo_usage;

@pytest.fixture(scope="module")
def general_config() -> StarknetGeneralConfig:
    return StarknetGeneralConfig(
        sequencer_address=1991,
        starknet_os_config=StarknetOsConfig(fee_token_address=2022),
        cairo_resource_fee_weights={
            N_STEPS_RESOURCE: 1.0,
            **{builtin: 1.0 for builtin in ALL_BUILTINS.except_for(KECCAK_BUILTIN).with_suffix()},
        },
    )

@pytest.fixture(scope="module")
def cairo_resource_usage() -> Dict[str, int]:
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
    l1_gas_by_cairo_usage = cairo_resource_usage.get(N_STEPS_RESOURCE);
    assert_eq!(l1_gas_by_cairo_usage, calculate_l1_gas_by_cairo_usage(
            block_context, cairo_resource_usage).ceil()
    );

    // Negative flow.
    // Pass dict with extra key.
    let invalid_cairo_resource_usage = cairo_resource_usage.clone();
    invalid_cairo_resource_usage.insert("bad_resource_name"=17);
    let result = std::panic::catch_unwind(|| 
        calculate_l1_gas_by_cairo_usage(block_context, invalid_cairo_resource_usage));
    assert!(result.is_err());  //probe further for specific error type here, if desired

    with pytest.raises(
        AssertionError,
        match="Cairo resource names must be contained in fee weights dict.",
    ):
        
}
