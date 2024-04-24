use std::sync::Arc;

use cairo_felt::Felt252;

use super::versioned_state_proxy::ThreadSafeVersionedState;
use super::TxIndex;
use crate::abi::abi_utils::get_fee_token_var_address;
use crate::concurrency::fee_utils::fix_concurrency_fee_transfer_call_info;
use crate::context::BlockContext;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::fee_utils::get_sequencer_address_and_keys;
use crate::state::cached_state::{CachedState, ContractClassMapping, StateMaps};
use crate::state::state_api::{State, StateReader};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transactions::ExecutableTransaction;

pub fn commit_transaction<S: StateReader>(
    versioned_state: &mut ThreadSafeVersionedState<S>,
    tx_index: &TxIndex,
    block_context: &mut BlockContext,
    tx_list: Vec<&AccountTransaction>,
    read_set: &StateMaps,
    transactions_info: &mut [TransactionExecutionResult<TransactionExecutionInfo>],
) {
    let result_tx_info = &mut transactions_info[*tx_index];
    if result_tx_info.is_err() {
        return;
    }

    let account_tx = tx_list[*tx_index];
    let tx_context = Arc::new(block_context.to_tx_context(account_tx));
    // TODO(meshi 20/05/2024): chenge this when the chached state will be updated to fit concurrency
    // mode.
    let mut cached_state = CachedState::from(versioned_state.pin_version(*tx_index));
    let mut transactional_state = CachedState::create_transactional(&mut cached_state);
    let (sequencer_balance_key_low, _sequencer_balance_key_high) =
        get_sequencer_address_and_keys(&tx_context.block_context);

    if !versioned_state.validate_read_set(*tx_index, read_set) {
        // Revalidate failed rexecute the transaction and commit.
        block_context.concurrency_mode = false;
        transactions_info[*tx_index] =
            account_tx.execute_raw(&mut transactional_state, block_context, true, true);
        if transactions_info[*tx_index].is_err() {
            return;
        }
        versioned_state.apply_writes(
            *tx_index,
            &transactional_state.cache.borrow_mut().writes,
            &ContractClassMapping::default(),
        );
        // TODO(meshi 15/05/2024): Ask the bouncer if the tx has palce in the current block.
        return;
    }

    // revalidate seq reads passed
    if let Ok(tx_info) = result_tx_info.as_mut() {
        // TODO(meshi 15/05/2024): Ask the bouncer if the tx has palce in the current block.
        if tx_context.tx_info.sender_address() != block_context.block_info.sequencer_address {
            // fix the call info
            let sequencer_balance = versioned_state
                .pin_version(*tx_index)
                .get_storage_at(tx_context.fee_token_address(), sequencer_balance_key_low);
            if let Some(call_info) = tx_info.fee_transfer_call_info.as_mut() {
                fix_concurrency_fee_transfer_call_info(call_info, sequencer_balance.unwrap());
            }

            // update sequencer balance
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
    }
}
