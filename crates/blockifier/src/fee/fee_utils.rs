use std::collections::HashSet;

use starknet_api::transaction::Fee;

use crate::block_context::BlockContext;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionResult};

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

/// Calculates the fee that should be charged, given execution resources.
/// We add the l1_gas_usage (which may include, for example, the direct cost of L2-to-L1 messages)
/// to the gas consumed by Cairo VM resource and multiply by the L1 gas price.
pub fn calculate_tx_fee(
    l1_gas_usage: usize,
    vm_resources: &ResourcesMapping,
    block_context: &BlockContext,
) -> TransactionExecutionResult<Fee> {
    let l1_gas_by_cairo_usage = calculate_l1_gas_by_cairo_usage(block_context, vm_resources)?;
    let total_l1_gas_usage = l1_gas_usage as f64 + l1_gas_by_cairo_usage;
    let gas_price = block_context.gas_price;

    Ok(Fee(total_l1_gas_usage.ceil() as u128 * gas_price))
}
