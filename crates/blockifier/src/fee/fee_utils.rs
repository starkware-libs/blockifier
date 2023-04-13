use std::collections::{HashMap, HashSet};

use crate::abi::constants;
use crate::block_context::BlockContext;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionResult};

#[cfg(test)]
#[path = "fee_test.rs"]
pub mod test;

pub fn extract_l1_gas_and_cairo_usage(
    resources: &ResourcesMapping,
) -> (usize, HashMap<String, usize>) {
    let mut cairo_resource_usage = resources.0.clone();
    let l1_gas_usage = cairo_resource_usage
        .remove(constants::GAS_USAGE)
        .expect("`ResourcesMapping` does not have the key `l1_gas_usage`.");

    (l1_gas_usage, cairo_resource_usage)
}

/// Calculates the L1 gas consumed when submitting the underlying Cairo program to SHARP.
/// I.e., returns the heaviest Cairo resource weight (in terms of L1 gas), as the size of
/// a proof is determined similarly - by the (normalized) largest segment.
pub fn calculate_l1_gas_by_cairo_usage(
    block_context: &BlockContext,
    cairo_resource_usage: &ResourcesMapping,
) -> TransactionExecutionResult<f64> {
    let cairo_resource_fee_weights = &block_context.cairo_resource_fee_weights;
    let cairo_resource_names = HashSet::<&String>::from_iter(cairo_resource_usage.0.keys());
    if !cairo_resource_names.is_subset(&HashSet::from_iter(cairo_resource_fee_weights.keys())) {
        return Err(TransactionExecutionError::CairoResourcesNotContainedInFeeWeights);
    };

    // Convert Cairo usage to L1 gas usage.
    let cairo_l1_gas_usage = cairo_resource_fee_weights
        .iter()
        .map(|(key, resource_val)| {
            (*resource_val) * cairo_resource_usage.0.get(key).cloned().unwrap_or_default() as f64
        })
        .fold(f64::NAN, f64::max);

    Ok(cairo_l1_gas_usage)
}
