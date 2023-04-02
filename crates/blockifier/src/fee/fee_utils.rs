use std::collections::{HashMap, HashSet};

use itertools::max;

use crate::block_context::BlockContext;
use crate::transaction::objects::ResourcesMapping;

#[cfg(test)]
#[path = "fee_test.rs"]
pub mod test;

pub fn extract_l1_gas_and_cairo_usage(
    resources: &ResourcesMapping,
) -> (usize, HashMap<String, usize>) {
    let mut cairo_resource_usage = resources.0.clone();
    let l1_gas_usage = cairo_resource_usage
        .remove("l1_gas_usage")
        .expect("`ResourcesMapping` does not have the key `l1_gas_usage`.");

    (l1_gas_usage, cairo_resource_usage)
}

/// Calculates the L1 gas consumed when submitting the underlying Cairo program to SHARP.
/// I.e., returns the heaviest Cairo resource weight (in terms of L1 gas), as the size of
/// a proof is determined similarly - by the (normalized) largest segment.
pub fn calculate_l1_gas_by_cairo_usage(
    block_context: &BlockContext,
    cairo_resource_usage: &ResourcesMapping,
) -> usize {
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
                Some(usage_val) => (*resource_val as usize) * (*usage_val),
                None => 0_usize,
            },
        ));
    match cairo_l1_gas_usage {
        None => panic!("block_context.cairo_resource_fee_weights can not be empty."),
        Some(gas_usage) => gas_usage,
    }
}
