use std::collections::HashSet;

use starknet_api::transaction::Fee;

use crate::abi::constants;
use crate::block_context::BlockContext;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{
    HasTransactionVersion, ResourcesMapping, TransactionExecutionResult,
};

#[cfg(test)]
#[path = "fee_test.rs"]
pub mod test;

pub fn extract_l1_gas_and_vm_usage(resources: &ResourcesMapping) -> (usize, ResourcesMapping) {
    let mut vm_resource_usage = resources.0.clone();
    let l1_gas_usage = vm_resource_usage
        .remove(constants::GAS_USAGE)
        .expect("`ResourcesMapping` does not have the key `l1_gas_usage`.");

    (l1_gas_usage, ResourcesMapping(vm_resource_usage))
}

/// Calculates the L1 gas consumed when submitting the underlying Cairo program to SHARP.
/// I.e., returns the heaviest Cairo resource weight (in terms of L1 gas), as the size of
/// a proof is determined similarly - by the (normalized) largest segment.
pub fn calculate_l1_gas_by_vm_usage(
    block_context: &BlockContext,
    vm_resource_usage: &ResourcesMapping,
) -> TransactionExecutionResult<f64> {
    let vm_resource_fee_costs = &block_context.vm_resource_fee_cost;
    let vm_resource_names = HashSet::<&String>::from_iter(vm_resource_usage.0.keys());
    if !vm_resource_names.is_subset(&HashSet::from_iter(vm_resource_fee_costs.keys())) {
        return Err(TransactionExecutionError::CairoResourcesNotContainedInFeeCosts);
    };

    // Convert Cairo usage to L1 gas usage.
    let vm_l1_gas_usage = vm_resource_fee_costs
        .iter()
        .map(|(key, resource_val)| {
            (*resource_val) * vm_resource_usage.0.get(key).cloned().unwrap_or_default() as f64
        })
        .fold(f64::NAN, f64::max);

    Ok(vm_l1_gas_usage)
}

/// Calculates the fee that should be charged, given execution resources.
/// We add the l1_gas_usage (which may include, for example, the direct cost of L2-to-L1 messages)
/// to the gas consumed by Cairo VM resource and multiply by the L1 gas price.
pub fn calculate_tx_fee(
    resources: &ResourcesMapping,
    block_context: &BlockContext,
    has_version: &dyn HasTransactionVersion,
) -> TransactionExecutionResult<Fee> {
    let (l1_gas_usage, vm_resources) = extract_l1_gas_and_vm_usage(resources);
    let l1_gas_by_vm_usage = calculate_l1_gas_by_vm_usage(block_context, &vm_resources)?;
    let total_l1_gas_usage = l1_gas_usage as f64 + l1_gas_by_vm_usage;

    // TODO(Dori, 1/9/2023): NEW_TOKEN_SUPPORT gas price depends on transaction version.
    Ok(Fee(
        total_l1_gas_usage.ceil() as u128 * block_context.gas_prices.get_for_version(has_version)
    ))
}
