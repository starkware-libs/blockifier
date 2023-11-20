use num_bigint::BigUint;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, contract_address, patricia_key, stark_felt};

use crate::abi::abi_utils::{get_storage_var_address, selector_from_name};
use crate::execution::call_info::Retdata;
use crate::execution::entry_point::CallEntryPoint;
use crate::fee::strk_gas_price::errors::StrkGasPriceCalcError;
use crate::fee::strk_gas_price::gas_price::{PoolState, PoolStateAggregator};
use crate::retdata;
use crate::state::state_api::StateReader;
use crate::test_utils::dict_state_reader::deprecated_create_test_state;
use crate::test_utils::{RESERVE_0, RESERVE_1, TEST_PAIR_SKELETON_CONTRACT_ADDRESS1};

/// Sanity tests for STRK<->ETH price computation.
#[test]
fn test_convert_wei_to_strk() {
    let (wei_1, wei_2, wei_3) =
        (BigUint::from(10_u32), BigUint::from(14_u32), BigUint::from(12_u32));
    let (strk_1, strk_2, strk_3, strk_4) = (
        BigUint::from(50_u32),
        BigUint::from(42_u32),
        BigUint::from(24_u32),
        BigUint::from(150_u32),
    );
    let state_1 = PoolState { total_wei: wei_1.clone(), total_strk: strk_1 };
    let state_2 = PoolState { total_wei: wei_2, total_strk: strk_2 };
    let state_3 = PoolState { total_wei: wei_3, total_strk: strk_3 };
    let state_4 = PoolState { total_wei: wei_1, total_strk: strk_4 };
    let wei_amount = BigUint::from(10_000_000_000_u64);

    // Bad flow: ratio computation on empty array.
    assert!(matches!(PoolStateAggregator::new(&[]), Err(StrkGasPriceCalcError::NoPoolStatesError)));

    // Convert Wei -> STRK with a single pool state.
    assert_eq!(
        PoolStateAggregator::new(&[state_1.clone()])
            .unwrap()
            .convert_wei_to_strk(wei_amount.clone()),
        (state_1.total_strk.clone() * wei_amount.clone()) / state_1.total_wei.clone()
    );

    // Convert Wei -> STRK with multiple pool states, no equal weight partition.
    assert_eq!(
        PoolStateAggregator::new(&[state_3.clone(), state_1.clone()])
            .unwrap()
            .convert_wei_to_strk(wei_amount.clone()),
        (state_3.total_strk.clone() * wei_amount.clone()) / state_3.total_wei.clone()
    );
    assert_eq!(
        PoolStateAggregator::new(&[state_3, state_1.clone(), state_2.clone()])
            .unwrap()
            .convert_wei_to_strk(wei_amount.clone()),
        (state_2.total_strk.clone() * wei_amount.clone()) / state_2.total_wei.clone()
    );

    // Convert Wei -> STRK with multiple pool states with equal weight partition.
    assert_eq!(
        PoolStateAggregator::new(&[state_1.clone(), state_4.clone()])
            .unwrap()
            .convert_wei_to_strk(wei_amount.clone()),
        ((state_1.total_strk + state_4.total_strk) * wei_amount)
            / (state_1.total_wei + state_4.total_wei)
    );
}

#[test]
// Test that the pair contract returns the correct reserve values.
fn test_get_reserves() {
    let contract_address = contract_address!(TEST_PAIR_SKELETON_CONTRACT_ADDRESS1);
    let mut state = deprecated_create_test_state();
    // Get reserve0 value through storage read.
    let mut storage_key = get_storage_var_address("_reserve0", &[]);
    let reserve0 = state.get_storage_at(contract_address, storage_key).unwrap();
    // Get reserve1 value through storage read.
    storage_key = get_storage_var_address("_reserve1", &[]);
    let reserve1 = state.get_storage_at(contract_address, storage_key).unwrap();

    // Verify that the stored values are as expected through storage read.
    assert_eq!(reserve0, stark_felt!(RESERVE_0));
    assert_eq!(reserve1, stark_felt!(RESERVE_1));

    // Verify that the returned values are as expected through entry point call.
    let expected_result = retdata![
        stark_felt!(RESERVE_0), // reserve0_low
        StarkFelt::ZERO,        // reserve0_high
        stark_felt!(RESERVE_1), // reserve1_low
        StarkFelt::ZERO,        // reserve1_high
        StarkFelt::ZERO         // block_timestamp_last
    ];

    let entry_point_call = CallEntryPoint {
        calldata: calldata![],
        entry_point_selector: selector_from_name("get_reserves"),
        storage_address: contract_address,
        ..Default::default()
    };
    let result = entry_point_call.execute_directly(&mut state).unwrap().execution.retdata;

    assert_eq!(result, expected_result);
}
