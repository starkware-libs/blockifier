use num_bigint::BigUint;

use crate::fee::errors::StrkGasPriceCalcError;
use crate::fee::strk_gas_price::{PoolState, PoolStateAggregator};

/// Sanity tests for STRK<->ETH price computation.
#[test]
fn test_convert_wei_to_strk() {
    let (wei_1, wei_2, wei_3) =
        (BigUint::from(10_u32), BigUint::from(14_u32), BigUint::from(12_u32));
    let (strk_1, strk_2, strk_3) =
        (BigUint::from(50_u32), BigUint::from(42_u32), BigUint::from(24_u32));
    let state_1 = PoolState { total_wei: wei_1.clone(), total_strk: strk_1 };
    let state_2 = PoolState { total_wei: wei_2, total_strk: strk_2 };
    let state_3 = PoolState { total_wei: wei_3, total_strk: strk_3 };
    let state_4 = PoolState { total_wei: wei_1, total_strk: BigUint::from(150_u32) };
    let wei_amount = BigUint::from(10_000_000_000_u64);

    // Bad flow: ratio computation on empty array.
    assert!(matches!(PoolStateAggregator::new(&[]), Err(StrkGasPriceCalcError::NoPoolStatesError)));

    // convert Wei -> STRK with a single pool state.
    assert_eq!(
        PoolStateAggregator::new(&[state_1.clone()])
            .unwrap()
            .convert_wei_to_strk(wei_amount.clone()),
        (state_1.total_strk.clone() * wei_amount.clone()) / state_1.total_wei.clone()
    );

    // convert Wei -> STRK with multiple pool states, no equal weight partition.
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

    // convert Wei -> STRK with multiple pool states with equal weight partition.
    assert_eq!(
        PoolStateAggregator::new(&[state_1.clone(), state_4.clone()])
            .unwrap()
            .convert_wei_to_strk(wei_amount.clone()),
        ((state_1.total_strk + state_4.total_strk) * wei_amount)
            / (state_1.total_wei + state_4.total_wei)
    );
}
