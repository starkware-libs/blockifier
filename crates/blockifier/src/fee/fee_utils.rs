use std::collections::HashSet;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{EventContent, EventData, EventKey, Fee};

use crate::abi::abi_utils::{get_fee_token_var_address, selector_from_name};
use crate::abi::constants;
use crate::abi::sierra_types::next_storage_key;
use crate::blockifier::block::BlockInfo;
use crate::context::{BlockContext, TransactionContext};
use crate::execution::call_info::{CallExecution, CallInfo, OrderedEvent, Retdata};
use crate::execution::entry_point::CallEntryPoint;
use crate::state::state_api::StateReader;
use crate::test_utils::prices::Prices;
use crate::transaction::errors::TransactionFeeError;
use crate::transaction::objects::{
    ExecutionResourcesTraits, FeeType, GasVector, HasRelatedFeeType, TransactionFeeResult,
    TransactionInfo, TransactionResources,
};
use crate::utils::u128_from_usize;
use crate::versioned_constants::VersionedConstants;

#[cfg(test)]
#[path = "fee_test.rs"]
pub mod test;

/// Calculates the L1 gas consumed when submitting the underlying Cairo program to SHARP.
/// I.e., returns the heaviest Cairo resource weight (in terms of L1 gas), as the size of
/// a proof is determined similarly - by the (normalized) largest segment.
pub fn calculate_l1_gas_by_vm_usage(
    versioned_constants: &VersionedConstants,
    vm_resource_usage: &ExecutionResources,
    n_reverted_steps: usize,
) -> TransactionFeeResult<GasVector> {
    // TODO(Yoni, 1/7/2024): rename vm -> cairo.
    let vm_resource_fee_costs = versioned_constants.vm_resource_fee_cost();
    let mut vm_resource_usage_for_fee = vm_resource_usage.prover_builtins();
    vm_resource_usage_for_fee.insert(
        constants::N_STEPS_RESOURCE.to_string(),
        vm_resource_usage.total_n_steps() + n_reverted_steps,
    );

    // Validate used Cairo resources.
    let used_resource_names = HashSet::<&String>::from_iter(vm_resource_usage_for_fee.keys());

    assert!(
        used_resource_names.is_subset(&HashSet::from_iter(vm_resource_fee_costs.keys())),
        "{:#?} should contain {:#?}",
        vm_resource_fee_costs.keys(),
        used_resource_names,
    );

    // Convert Cairo usage to L1 gas usage.
    let vm_l1_gas_usage = vm_resource_fee_costs
        .iter()
        .map(|(key, resource_val)| {
            ((*resource_val)
                * u128_from_usize(vm_resource_usage_for_fee.get(key).cloned().unwrap_or_default()))
            .ceil()
            .to_integer()
        })
        .fold(0, u128::max);

    Ok(GasVector::from_l1_gas(vm_l1_gas_usage))
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

/// Calculates the fee that should be charged, given transaction resources.
pub fn calculate_tx_fee(
    tx_resources: &TransactionResources,
    block_context: &BlockContext,
    fee_type: &FeeType,
) -> TransactionFeeResult<Fee> {
    let gas_vector = tx_resources
        .to_gas_vector(&block_context.versioned_constants, block_context.block_info.use_kzg_da)?;
    Ok(get_fee_by_gas_vector(&block_context.block_info, gas_vector, fee_type))
}

/// Returns the current fee balance and a boolean indicating whether the balance covers the fee.
pub fn get_balance_and_if_covers_fee(
    state: &mut dyn StateReader,
    tx_context: &TransactionContext,
    fee: Fee,
) -> TransactionFeeResult<(StarkFelt, StarkFelt, bool)> {
    let tx_info = &tx_context.tx_info;
    let (balance_low, balance_high) =
        state.get_fee_token_balance(tx_info.sender_address(), tx_context.fee_token_address())?;
    Ok((
        balance_low,
        balance_high,
        // TODO(Dori,1/10/2023): If/when fees can be more than 128 bit integers, this should be
        //   updated.
        balance_high > StarkFelt::from(0_u8) || balance_low >= StarkFelt::from(fee.0),
    ))
}
pub fn create_fee_transfer_call_info(
    call_entry_point: CallEntryPoint,
    block_context: &BlockContext,
    tx_info: &TransactionInfo,
    account_address: ContractAddress,
    lsb_amount: StarkFelt,
    event_name: &str,
    ret_value: Retdata,
    balance: u128,
) -> CallInfo {
    let fee_type = tx_info.fee_type();
    let expected_sequencer_address = block_context.block_info.sequencer_address;
    let expected_sequencer_address_felt = *expected_sequencer_address.0.key();
    // The most significant 128 bits of the expected amount transferred.
    let msb_expected_amount = stark_felt!(0_u8);
    let expected_fee_sender_address = *account_address.0.key();
    let expected_fee_transfer_event = OrderedEvent {
        order: 0,
        event: EventContent {
            keys: vec![EventKey(selector_from_name(event_name).0)],
            data: EventData(vec![
                expected_fee_sender_address,
                expected_sequencer_address_felt, // Recipient.
                lsb_amount,
                msb_expected_amount,
            ]),
        },
    };

    let sender_balance_key_low = get_fee_token_var_address(account_address);
    let sender_balance_key_high =
        next_storage_key(&sender_balance_key_low).expect("Cannot get sender balance high key.");
    let sequencer_balance_key_low = get_fee_token_var_address(expected_sequencer_address);
    let sequencer_balance_key_high = next_storage_key(&sequencer_balance_key_low)
        .expect("Cannot get sequencer balance high key.");
    CallInfo {
        call: call_entry_point,
        execution: CallExecution {
            retdata: ret_value,
            events: vec![expected_fee_transfer_event],
            ..Default::default()
        },
        resources: Prices::FeeTransfer(account_address, fee_type).into(),
        // We read sender balance, write (which starts with read) sender balance, then the same for
        // recipient. We read Uint256(BALANCE, 0) twice, then Uint256(0, 0) twice.
        storage_read_values: vec![
            stark_felt!(balance),
            stark_felt!(0_u8),
            stark_felt!(balance),
            stark_felt!(0_u8),
            stark_felt!(0_u8),
            stark_felt!(0_u8),
            stark_felt!(0_u8),
            stark_felt!(0_u8),
        ],
        accessed_storage_keys: HashSet::from_iter(vec![
            sender_balance_key_low,
            sender_balance_key_high,
            sequencer_balance_key_low,
            sequencer_balance_key_high,
        ]),
        ..Default::default()
    }
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
