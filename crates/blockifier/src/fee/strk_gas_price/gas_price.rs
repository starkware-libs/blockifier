use std::cmp::Ordering;

use num_bigint::BigUint;
use num_traits::Zero;

use crate::fee::strk_gas_price::errors::StrkGasPriceCalcError;

#[cfg(test)]
#[path = "gas_price_test.rs"]
pub mod test;

/// Struct representing the current state of a STRK<->ETH AMM pool.
#[derive(Clone, Debug)]
pub struct PoolState {
    pub total_wei: BigUint,
    pub total_fri: BigUint,
}

impl PoolState {
    pub fn tvl_in_wei(&self) -> BigUint {
        // Assumption on pool is the two pools have the same total value.
        self.total_wei.clone() << 1
    }
    /// Returns the result of comparing two pool states by STRK / Wei ratio.
    pub fn compare_fri_to_wei_ratio(&self, other: &Self) -> Ordering {
        //  a / b < c / d <=> a * d < c * b. The same is true for the other orders.
        let lhs = self.total_fri.clone() * other.total_wei.clone();
        let rhs = other.total_fri.clone() * self.total_wei.clone();
        lhs.cmp(&rhs)
    }
}

/// Struct representing aggregate of STRK<->ETH AMM pools.
/// Converts Wei to STRK at the STRK / Wei ratio of the weighted median pool state.
#[derive(Clone, Debug)]
pub struct PoolStateAggregator {
    // Pool states are sorted by STRK / Wei ratio.
    pub sorted_pool_states: Vec<PoolState>,
    // See PoolStateAggregator::calc_median_values() for more info on median calculation.
    pub median_pool_fri_tvl: BigUint,
    pub median_pool_wei_tvl: BigUint,
}

impl PoolStateAggregator {
    pub fn new(pool_states: &[PoolState]) -> Result<Self, StrkGasPriceCalcError> {
        if pool_states.is_empty() {
            return Err(StrkGasPriceCalcError::NoPoolStatesError);
        }

        let mut sorted_pool_states: Vec<PoolState> = pool_states.to_vec();
        sorted_pool_states.sort_unstable_by(|pool_state_a, pool_state_b| {
            pool_state_a.compare_fri_to_wei_ratio(pool_state_b)
        });

        let (median_pool_fri_tvl, median_pool_wei_tvl) =
            Self::calc_median_values(&sorted_pool_states);

        Ok(Self { sorted_pool_states, median_pool_fri_tvl, median_pool_wei_tvl })
    }

    /// Returns the STRK and Wei TVL of the weighted median pool state:
    /// The pool state with a STRK TVL / Wei TVL ratio such that the sum of the weights of the pool
    /// states with a smaller ratio is smaller or equal to half the total weight (and the same for
    /// pools with a larger ratio). If two such pools exist the average is returned.
    /// The pool states are weighted by the total TVL in Wei.
    /// This function assumes the given slice is sorted by STRK / Wei ratio.
    pub fn calc_median_values(sorted_pool_states: &[PoolState]) -> (BigUint, BigUint) {
        let total_weight: BigUint =
            sorted_pool_states.iter().map(|state| state.tvl_in_wei()).sum::<BigUint>();

        // Find index of weighted median STRK / Wei ratio.
        let mut current_weight: BigUint = BigUint::zero();
        let mut median_idx = 0;
        let equal_weight_partition: bool;
        loop {
            current_weight += sorted_pool_states[median_idx].tvl_in_wei().clone();
            if current_weight.clone() << 1 >= total_weight {
                equal_weight_partition = current_weight << 1 == total_weight;
                break;
            }
            median_idx += 1;
        }

        let median_pool_fri_tvl: BigUint;
        let median_pool_wei_tvl: BigUint;
        if equal_weight_partition {
            median_pool_fri_tvl = (sorted_pool_states[median_idx].total_fri.clone()
                + sorted_pool_states[median_idx + 1].total_fri.clone())
                / BigUint::from(2_u32);
            median_pool_wei_tvl = (sorted_pool_states[median_idx].total_wei.clone()
                + sorted_pool_states[median_idx + 1].total_wei.clone())
                / BigUint::from(2_u32);
        } else {
            median_pool_fri_tvl = sorted_pool_states[median_idx].total_fri.clone();
            median_pool_wei_tvl = sorted_pool_states[median_idx].total_wei.clone();
        }
        (median_pool_fri_tvl, median_pool_wei_tvl)
    }

    pub fn convert_wei_to_fri(&self, wei_amount: BigUint) -> BigUint {
        (wei_amount * self.median_pool_fri_tvl.clone()) / self.median_pool_wei_tvl.clone()
    }
}
