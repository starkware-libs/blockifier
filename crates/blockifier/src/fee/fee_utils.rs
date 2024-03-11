use std::collections::HashSet;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Fee;

use crate::abi::constants::{self, N_STEPS_RESOURCE};
use crate::blockifier::block::BlockInfo;
use crate::context::{BlockContext, TransactionContext};
use crate::state::state_api::StateReader;
use crate::transaction::errors::TransactionFeeError;
use crate::transaction::objects::{
    FeeType, GasVector, HasRelatedFeeType, ResourcesMapping, TransactionFeeResult, TransactionInfo,
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

pub fn extract_n_steps_gas_usage(resources: &ResourcesMapping) -> (usize, ResourcesMapping) {
    let mut vm_resource_usage = resources.0.clone();
    let l1_blob_gas_usage =
        vm_resource_usage.remove(constants::N_STEPS_RESOURCE).unwrap_or_default();
    (l1_blob_gas_usage, ResourcesMapping(vm_resource_usage))
}

/// Calculates the L1 gas consumed when submitting the underlying Cairo program to SHARP.
/// I.e., returns the heaviest Cairo resource weight (in terms of L1 gas), as the size of
/// a proof is determined similarly - by the (normalized) largest segment.
pub fn calculate_l1_gas_by_vm_usage(
    versioned_constants: &VersionedConstants,
    vm_resource_usage: &ExecutionResources,
) -> TransactionFeeResult<GasVector> {
    let vm_resource_fee_costs = versioned_constants.vm_resource_fee_cost();
    let vm_resource_names =
        HashSet::<&String>::from_iter(vm_resource_usage.builtin_instance_counter.keys());
    if !vm_resource_names.is_subset(&HashSet::from_iter(vm_resource_fee_costs.keys())) {
        return Err(TransactionFeeError::CairoResourcesNotContainedInFeeCosts);
    };
    let n_steps_gas_usage = u128_from_usize(vm_resource_usage.n_steps)
        * vm_resource_fee_costs
            .get(N_STEPS_RESOURCE)
            .cloned()
            .unwrap_or_default()
            .ceil()
            .to_integer();

    // Convert Cairo usage to L1 gas usage.
    let vm_l1_gas_usage = vm_resource_fee_costs
        .iter()
        .map(|(key, resource_val)| {
            ((*resource_val)
                * u128_from_usize(
                    vm_resource_usage
                        .builtin_instance_counter
                        .get(key)
                        .cloned()
                        .unwrap_or_default(),
                ))
            .ceil()
            .to_integer()
        })
        .fold(n_steps_gas_usage, u128::max);

    Ok(GasVector::from_l1_gas(vm_l1_gas_usage))
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
    let (n_steps, vm_resources) = extract_n_steps_gas_usage(&vm_resources);
    let execution_resources =
        ExecutionResources { n_steps, n_memory_holes: 0, builtin_instance_counter: vm_resources.0 };
    let vm_usage_gas_vector =
        calculate_l1_gas_by_vm_usage(versioned_constants, &execution_resources)?;

    Ok(GasVector {
        l1_gas: u128_from_usize(l1_gas_usage),
        l1_data_gas: u128_from_usize(l1_blob_gas_usage),
    } + vm_usage_gas_vector)
}

/// Converts the gas vector to a fee.
pub fn get_fee_by_gas_vector(
    block_info: &BlockInfo,
    gas_vector: GasVector,
    fee_type: &FeeType,
) -> Fee {
    gas_vector.saturated_cost(
        u128::from(block_info.gas_prices.get_gas_price_by_fee_type(fee_type)),
        u128::from(block_info.gas_prices.get_data_gas_price_by_fee_type(fee_type)),
    )
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
    tx_context: &TransactionContext,
    fee: Fee,
) -> TransactionFeeResult<(StarkFelt, StarkFelt, bool)> {
    let tx_info = &tx_context.tx_info;
    let (balance_low, balance_high) = state.get_fee_token_balance(
        tx_info.sender_address(),
        tx_context.block_context.chain_info.fee_token_address(&tx_info.fee_type()),
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
    tx_context: &TransactionContext,
) -> TransactionFeeResult<()> {
    let tx_info = &tx_context.tx_info;
    let committed_fee = match tx_info {
        TransactionInfo::Current(context) => {
            let l1_bounds = context.l1_resource_bounds()?;
            let max_amount: u128 = l1_bounds.max_amount.into();
            // Sender will not be charged by `max_price_per_unit`, but this check should not depend
            // on the current gas price.
            Fee(max_amount * l1_bounds.max_price_per_unit)
        }
        TransactionInfo::Deprecated(context) => context.max_fee,
    };
    let (balance_low, balance_high, can_pay) =
        get_balance_and_if_covers_fee(state, tx_context, committed_fee)?;
    if can_pay {
        Ok(())
    } else {
        Err(match tx_info {
            TransactionInfo::Current(context) => {
                let l1_bounds = context.l1_resource_bounds()?;
                TransactionFeeError::L1GasBoundsExceedBalance {
                    max_amount: l1_bounds.max_amount,
                    max_price: l1_bounds.max_price_per_unit,
                    balance_low,
                    balance_high,
                }
            }
            TransactionInfo::Deprecated(context) => TransactionFeeError::MaxFeeExceedsBalance {
                max_fee: context.max_fee,
                balance_low,
                balance_high,
            },
        })
    }
}
