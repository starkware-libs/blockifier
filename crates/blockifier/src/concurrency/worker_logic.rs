use std::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

use cairo_felt::Felt252;

use super::versioned_state_proxy::ThreadSafeVersionedState;
use super::TxIndex;
use crate::abi::abi_utils::get_fee_token_var_address;
use crate::concurrency::fee_utils::fix_concurrency_fee_transfer_call_info;
use crate::concurrency::versioned_state_proxy::VersionedStateProxy;
use crate::context::{BlockContext, TransactionContext};
use crate::execution::call_info;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::fee_utils::get_sequencer_address_and_keys;
use crate::state::cached_state::{CachedState, StateCache, StateMaps};
use crate::state::state_api::{State, StateReader};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transactions::ExecutableTransaction;

// All transactions only uptate the sequencer balance when commited,
// these changes are not visible to other transactions through execution.
// Therefore we need to check that the value read by the transaction is still valid.
// This function will return false if the transaction with tx_index read the sequencer balance
// before the previous transaction was commited.
pub fn revalidate_sequencer_balance_reads<S: StateReader>(
    versioned_state: &mut VersionedStateProxy<S>,
    tx_context: &TransactionContext,
    read_set: &StateMaps,
) -> bool {
    let fee_token_address = tx_context.fee_token_address();
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_address_and_keys(&tx_context.block_context);
    let mut sequencer_balance_storage_reads = HashMap::new();
    for seq_key in [sequencer_balance_key_low, sequencer_balance_key_high] {
        if let Some(value) = read_set.storage.get(&(fee_token_address, seq_key)) {
            sequencer_balance_storage_reads.insert((fee_token_address, seq_key), *value);
        };
    }

    if sequencer_balance_storage_reads.is_empty() {
        return true;
    }

    let new_state_cache = &mut StateMaps {
            storage: sequencer_balance_storage_reads,
            ..StateMaps::default()
    };
    versioned_state
        .state
        .lock()
        .unwrap()
        .validate_read_set(versioned_state.tx_index, new_state_cache)
}

pub fn commit_transaction<S: StateReader>(
    versioned_state: &mut ThreadSafeVersionedState<S>,
    tx_index: &TxIndex,
    block_context: &mut BlockContext,
    tx_list: Vec<&AccountTransaction>,
    read_set: &StateMaps,
    transactions_info: &mut [TransactionExecutionResult<TransactionExecutionInfo>],
) {
    let mut result_tx_info = &transactions_info[*tx_index];
    if result_tx_info.is_err() {
        // update commmit index
        return;
    }
    if let Ok(tx_info) = &mut result_tx_info {
        let account_tx = tx_list[*tx_index];
        let tx_context = Arc::new(block_context.to_tx_context(account_tx));
        let mut cached_state = CachedState::from(versioned_state.pin_version(*tx_index));
        // TODO(Meshi): chenge this when the chached state will be updated to fit concurrency mode.
        let mut transactional_state = CachedState::create_transactional(&mut cached_state);
        let (sequencer_balance_key_low, _sequencer_balance_key_high) =
            get_sequencer_address_and_keys(&tx_context.block_context);
        if tx_context.tx_info.sender_address() == block_context.block_info.sequencer_address {
            // check if it has place in the bouncer
            // update commmit index
            return;
        }
        if !revalidate_sequencer_balance_reads(
            &mut versioned_state.pin_version(*tx_index),
            &tx_context,
            read_set,
        ) {
            block_context.concurrency_mode = false;
            account_tx.execute_raw(&mut transactional_state, block_context, true, true).unwrap();
            // check if it has place in the bouncer
        } else {
            // check if it has place in the bouncer
            let sequencer_balance = versioned_state
                .pin_version(*tx_index)
                .get_storage_at(tx_context.fee_token_address(), sequencer_balance_key_low);
            if let Some(call_info) = tx_info.fee_transfer_call_info.as_mut() {
                fix_concurrency_fee_transfer_call_info(call_info, sequencer_balance.unwrap());
            }
        }
        let sender_balance_key = get_fee_token_var_address(tx_context.fee_token_address());
        let sender_balance_value = transactional_state
            .get_storage_at(tx_context.fee_token_address(), sender_balance_key)
            .unwrap();
        let value = stark_felt_to_felt(sender_balance_value) + Felt252::from(tx_info.actual_fee.0);
        transactional_state
            .set_storage_at(
                tx_context.fee_token_address(),
                sender_balance_key,
                felt_to_stark_felt(&value),
            )
            .unwrap();
    }

    // update commmit index
}
