use std::sync::Arc;

use cairo_felt::Felt252;

use super::versioned_state_proxy::ThreadSafeVersionedState;
use super::TxIndex;
use crate::abi::abi_utils::get_fee_token_var_address;
use crate::concurrency::fee_utils::fill_sequencer_balance_reads;
use crate::context::BlockContext;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::state::cached_state::{CachedState, ContractClassMapping, StateMaps};
use crate::state::state_api::{State, StateReader};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transactions::ExecutableTransaction;

pub fn try_commit_transaction<S: StateReader>(
    versioned_state: &mut ThreadSafeVersionedState<S>,
    tx_index: TxIndex,
    block_context: &mut BlockContext,
    tx_list: Vec<&AccountTransaction>,
    read_set: &StateMaps,
    transactions_info: &mut [TransactionExecutionResult<TransactionExecutionInfo>],
) -> bool {
    let result_tx_info = &mut transactions_info[tx_index];
    if result_tx_info.is_err() {
        return true;
    }

    let account_tx = tx_list[tx_index];
    let tx_context = Arc::new(block_context.to_tx_context(account_tx));
    // TODO(meshi 20/05/2024): chenge this when the chached state will be updated to fit concurrency
    // mode.
    let mut cached_state = CachedState::from(versioned_state.pin_version(tx_index));
    let mut transactional_state = CachedState::create_transactional(&mut cached_state);
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(&tx_context.block_context);

    if !versioned_state.validate_read_set(tx_index, read_set) {
        // Revalidate failed: re-execute the transaction, and commit.
        block_context.concurrency_mode = false;
        transactions_info[tx_index] =
            account_tx.execute_raw(&mut transactional_state, block_context, true, true);
        if transactions_info[tx_index].is_err() {
            return true;
        }
        versioned_state.apply_writes(
            tx_index,
            &transactional_state.cache.borrow_mut().writes,
            &ContractClassMapping::default(),
        );
        // TODO(Meshi, 01/06/2024): check if this is also needed in the bouncer.
        return true;
    }

    // Revalidate succeeded
    if let Ok(tx_info) = result_tx_info.as_mut() {
        // TODO(Meshi, 01/06/2024): check if this is also needed in the bouncer.
        if tx_context.tx_info.sender_address() != block_context.block_info.sequencer_address {
            // Fix the call info.
            let sequencer_balance_low = versioned_state
                .pin_version(tx_index)
                .get_storage_at(tx_context.fee_token_address(), sequencer_balance_key_low);
            let sequencer_balance_high = versioned_state
                .pin_version(tx_index)
                .get_storage_at(tx_context.fee_token_address(), sequencer_balance_key_high);

            if let Some(fee_transfer_call_info) = tx_info.fee_transfer_call_info.as_mut() {
                fill_sequencer_balance_reads(
                    fee_transfer_call_info,
                    sequencer_balance_low.unwrap(),
                    sequencer_balance_high.unwrap(),
                );
            }

            // Update sequencer balance.
            let seq_balance_key = get_fee_token_var_address(tx_context.fee_token_address());
            let seq_balance_value = transactional_state
                .get_storage_at(tx_context.fee_token_address(), seq_balance_key)
                .unwrap();
            let value = stark_felt_to_felt(seq_balance_value) + Felt252::from(tx_info.actual_fee.0);
            transactional_state
                .set_storage_at(
                    tx_context.fee_token_address(),
                    seq_balance_key,
                    felt_to_stark_felt(&value),
                )
                .unwrap();
        }
        return true;
    }
    false
}
