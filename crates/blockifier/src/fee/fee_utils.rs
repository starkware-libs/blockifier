use std::collections::HashSet;

use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Fee;

use crate::abi::constants;
use crate::block_context::{BlockContext, BlockInfo, ChainInfo};
use crate::state::state_api::StateReader;
use crate::transaction::errors::TransactionFeeError;
use crate::transaction::objects::{
    AccountTransactionContext, FeeType, GasVector, HasRelatedFeeType, ResourcesMapping,
    TransactionFeeResult,
};
use crate::utils::u128_from_usize;
use crate::versioned_constants::VersionedConstants;

#[cfg(test)]
#[path = "fee_test.rs"]
pub mod test;

pub fn extract_l1_gas_and_vm_usage(resources: &ResourcesMapping) -> (usize, ResourcesMapping) {
    let mut vm_resource_usage = resources.0.clone();
    let l1_gas_usage = vm_resource_usage
        .remove(constants::L1_GAS_USAGE)
        .expect("`ResourcesMapping` does not have the key `l1_gas_usage`.");

    (l1_gas_usage, ResourcesMapping(vm_resource_usage))
}

pub fn extract_l1_blob_gas_usage(resources: &ResourcesMapping) -> (usize, ResourcesMapping) {
    let mut vm_resource_usage = resources.0.clone();
    let l1_blob_gas_usage = vm_resource_usage
        .remove(constants::BLOB_GAS_USAGE)
        .expect("`ResourcesMapping` does not have the key `blob_gas_usage`.");

    (l1_blob_gas_usage, ResourcesMapping(vm_resource_usage))
}

/// Calculates the L1 gas consumed when submitting the underlying Cairo program to SHARP.
/// I.e., returns the heaviest Cairo resource weight (in terms of L1 gas), as the size of
/// a proof is determined similarly - by the (normalized) largest segment.
pub fn calculate_l1_gas_by_vm_usage(
    versioned_constants: &VersionedConstants,
    vm_resource_usage: &ResourcesMapping,
) -> TransactionFeeResult<f64> {
    let vm_resource_fee_costs = &versioned_constants.vm_resource_fee_cost;
    let vm_resource_names = HashSet::<&String>::from_iter(vm_resource_usage.0.keys());
    if !vm_resource_names.is_subset(&HashSet::from_iter(vm_resource_fee_costs.keys())) {
        return Err(TransactionFeeError::CairoResourcesNotContainedInFeeCosts);
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
pub fn calculate_tx_gas_vector(
    resources: &ResourcesMapping,
    versioned_constants: &VersionedConstants,
) -> TransactionFeeResult<GasVector> {
    let (l1_gas_usage, vm_resources) = extract_l1_gas_and_vm_usage(resources);
    let (l1_blob_gas_usage, vm_resources) = extract_l1_blob_gas_usage(&vm_resources);
    let l1_gas_by_vm_usage = calculate_l1_gas_by_vm_usage(versioned_constants, &vm_resources)?;
    let total_l1_gas_usage = l1_gas_usage as f64 + l1_gas_by_vm_usage;

    Ok(GasVector {
        l1_gas: total_l1_gas_usage.ceil() as u128,
        blob_gas: u128_from_usize(l1_blob_gas_usage)
            .expect("Conversion from usize to u128 should not fail."),
    })
}

pub fn get_fee_by_gas_vector(
    block_info: &BlockInfo,
    gas_vector: GasVector,
    fee_type: &FeeType,
) -> Fee {
    Fee(gas_vector.l1_gas * block_info.gas_prices.get_gas_price_by_fee_type(fee_type)
        + gas_vector.blob_gas * block_info.gas_prices.get_data_gas_price_by_fee_type(fee_type))
}

/// Calculates the fee that should be charged, given execution resources.
pub fn calculate_tx_fee(
    resources: &ResourcesMapping,
    block_context: &BlockContext,
    fee_type: &FeeType,
) -> TransactionFeeResult<Fee> {
    let gas_vector = calculate_tx_gas_vector(resources, &block_context.versioned_constants)?;
    Ok(get_fee_by_gas_vector(&block_context.block_info, gas_vector, fee_type))
}

/// Returns the current fee balance and a boolean indicating whether the balance covers the fee.
pub fn get_balance_and_if_covers_fee(
    state: &mut dyn StateReader,
    account_tx_context: &AccountTransactionContext,
    chain_info: &ChainInfo,
    fee: Fee,
) -> TransactionFeeResult<(StarkFelt, StarkFelt, bool)> {
    let (balance_low, balance_high) = state.get_fee_token_balance(
        account_tx_context.sender_address(),
        chain_info.fee_token_address(&account_tx_context.fee_type()),
    )?;
    Ok((
        balance_low,
        balance_high,
        // TODO(Dori,1/10/2023): If/when fees can be more than 128 bit integers, this should be
        //   updated.
        balance_high > StarkFelt::from(0_u8) || balance_low >= StarkFelt::from(fee.0),
    ))
}

/// Verifies that, given the current state, the account can cover the resource upper bounds.
/// Error may indicate insufficient balance, or some other error.
pub fn verify_can_pay_committed_bounds(
    state: &mut dyn StateReader,
    account_tx_context: &AccountTransactionContext,
    chain_info: &ChainInfo,
) -> TransactionFeeResult<()> {
    let committed_fee = match account_tx_context {
        AccountTransactionContext::Current(context) => {
            let l1_bounds = context.l1_resource_bounds()?;
            let max_amount: u128 = l1_bounds.max_amount.into();
            // Sender will not be charged by `max_price_per_unit`, but this check should not depend
            // on the current gas price.
            Fee(max_amount * l1_bounds.max_price_per_unit)
        }
        AccountTransactionContext::Deprecated(context) => context.max_fee,
    };
    let (balance_low, balance_high, can_pay) =
        get_balance_and_if_covers_fee(state, account_tx_context, chain_info, committed_fee)?;
    if can_pay {
        Ok(())
    } else {
        Err(match account_tx_context {
            AccountTransactionContext::Current(context) => {
                let l1_bounds = context.l1_resource_bounds()?;
                TransactionFeeError::L1GasBoundsExceedBalance {
                    max_amount: l1_bounds.max_amount,
                    max_price: l1_bounds.max_price_per_unit,
                    balance_low,
                    balance_high,
                }
            }
            AccountTransactionContext::Deprecated(context) => {
                TransactionFeeError::MaxFeeExceedsBalance {
                    max_fee: context.max_fee,
                    balance_low,
                    balance_high,
                }
            }
        })
    }
}
