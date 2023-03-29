use std::collections::HashSet;

use itertools::max;

use crate::block_context::BlockContext;
use crate::transaction::objects::ResourcesMapping;

/// Calculates the L1 gas consumed when submitting the underlying Cairo program to SHARP.
/// I.e., returns the heaviest Cairo resource weight (in terms of L1 gas), as the size of
/// a proof is determined similarly - by the (normalized) largest segment.
pub fn calculate_l1_gas_by_cairo_usage(
    block_context: &BlockContext,
    cairo_resource_usage: &ResourcesMapping,
) -> u64 {
    let cairo_resource_fee_weights = &block_context.cairo_resource_fee_weights;
    let cairo_resource_names = HashSet::<&String>::from_iter(cairo_resource_usage.0.keys());
    assert!(
        cairo_resource_names.is_subset(&HashSet::from_iter(cairo_resource_fee_weights.keys())),
        "Cairo resource names must be contained in fee weights dict."
    );

    // Convert Cairo usage to L1 gas usage.
    let cairo_l1_gas_usage =
        max(cairo_resource_fee_weights.iter().map(
            |(key, resource_val)| match cairo_resource_usage.0.get(key) {
                Some(usage_val) => u64::from(*resource_val) * ((*usage_val) as u64),
                None => 0 as u64,
            },
        ));
    match cairo_l1_gas_usage {
        None => panic!("block_context.cairo_resource_fee_weights can not be empty."),
        Some(gas_usage) => gas_usage,
    }
}
