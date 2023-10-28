use std::collections::{BTreeMap, HashSet};

use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Fee, Resource, ResourceBounds, ResourceBoundsMapping};

use crate::abi::constants;
use crate::block_context::BlockContext;
use crate::state::state_api::StateReader;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{
    AccountTransactionContext, FeeType, HasRelatedFeeType, ResourcesMapping,
    TransactionExecutionResult,
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

/// Computes and returns the total L1 gas consumption.
/// We add the l1_gas_usage (which may include, for example, the direct cost of L2-to-L1 messages)
/// to the gas consumed by Cairo VM resource.
pub fn calculate_tx_l1_gas_usage(
    resources: &ResourcesMapping,
    block_context: &BlockContext,
) -> TransactionExecutionResult<u128> {
    let (l1_gas_usage, vm_resources) = extract_l1_gas_and_vm_usage(resources);
    let l1_gas_by_vm_usage = calculate_l1_gas_by_vm_usage(block_context, &vm_resources)?;
    let total_l1_gas_usage = l1_gas_usage as f64 + l1_gas_by_vm_usage;

    Ok(total_l1_gas_usage.ceil() as u128)
}

pub fn fee_by_l1_gas_usage(
    block_context: &BlockContext,
    l1_gas_usage: u128,
    fee_type: &FeeType,
) -> Fee {
    Fee(l1_gas_usage * block_context.gas_prices.get_by_fee_type(fee_type))
}

/// Calculates the fee that should be charged, given execution resources.
pub fn calculate_tx_fee(
    resources: &ResourcesMapping,
    block_context: &BlockContext,
    fee_type: &FeeType,
) -> TransactionExecutionResult<Fee> {
    Ok(fee_by_l1_gas_usage(
        block_context,
        calculate_tx_l1_gas_usage(resources, block_context)?,
        fee_type,
    ))
}

/// Returns the current fee balance and a boolean indicating whether the balance covers the fee.
fn get_balance_and_if_covers_fee(
    state: &mut dyn StateReader,
    account_tx_context: &AccountTransactionContext,
    block_context: &BlockContext,
    fee: Fee,
) -> TransactionExecutionResult<(StarkFelt, StarkFelt, bool)> {
    let (balance_low, balance_high) = state.get_fee_token_balance(
        &account_tx_context.sender_address(),
        &block_context.fee_token_address(&account_tx_context.fee_type()),
    )?;
    Ok((
        balance_low,
        balance_high,
        // TODO(Dori,1/10/2023): If/when fees can be more than 128 bit integers, this should be
        //   updated.
        balance_high > StarkFelt::from(0_u8) || balance_low >= StarkFelt::from(fee.0),
    ))
}

/// Verifies that, given the current state, the account can pay the given max fee.
/// Error may indicate insufficient balance, or some other error.
pub fn verify_can_pay_max_fee(
    state: &mut dyn StateReader,
    account_tx_context: &AccountTransactionContext,
    block_context: &BlockContext,
    max_fee: Fee,
) -> TransactionExecutionResult<()> {
    let (balance_low, balance_high, can_pay) =
        get_balance_and_if_covers_fee(state, account_tx_context, block_context, max_fee)?;
    if can_pay {
        Ok(())
    } else {
        Err(TransactionExecutionError::MaxFeeExceedsBalance { max_fee, balance_low, balance_high })
    }
}

/// Returns `true` if and only if the balance covers the fee.
pub fn can_pay_fee(
    state: &mut dyn StateReader,
    account_tx_context: &AccountTransactionContext,
    block_context: &BlockContext,
    fee: Fee,
) -> TransactionExecutionResult<bool> {
    let (_, _, can_pay) =
        get_balance_and_if_covers_fee(state, account_tx_context, block_context, fee)?;
    Ok(can_pay)
}

pub fn l1_resource_bounds(max_amount: u64, max_price: u128) -> ResourceBoundsMapping {
    // TODO(Dori, 1/11/2023): Once `From` is implemented on `ResourceBoundsMapping`, use it.
    ResourceBoundsMapping(BTreeMap::from([(
        Resource::L1Gas,
        ResourceBounds { max_amount, max_price_per_unit: max_price },
    )]))
}
