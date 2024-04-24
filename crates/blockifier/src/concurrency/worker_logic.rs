use std::sync::Arc;

use super::versioned_state_proxy::{ThreadSafeVersionedState, VersionedStateProxy};
use super::TxIndex;
use crate::concurrency::fee_utils::fill_sequencer_balance_reads;
use crate::context::{BlockContext, TransactionContext};
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::state::cached_state::{CachedState, StateMaps, TransactionalState};
use crate::state::state_api::{StateReader, StateResult};
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transaction_execution::Transaction;

pub fn commit_triggered_execute(
    _block_context: &mut BlockContext,
    _tx: &Transaction,
    _transactional_state: &mut TransactionalState<'_, impl StateReader>,
    _tx_versioned_state: &VersionedStateProxy<impl StateReader>,
) -> TransactionExecutionResult<TransactionExecutionInfo> {
    todo!()
}

fn add_fee_to_sequencer_balance(
    _tx_context: Arc<TransactionContext>,
    _tx_versioned_state: &VersionedStateProxy<impl StateReader>,
    _tx_info: &TransactionExecutionInfo,
    _transactional_state: &mut CachedState<impl StateReader>,
) -> StateResult<()> {
    todo!()
}

pub fn try_commit_transaction<S: StateReader>(
    versioned_state: &mut ThreadSafeVersionedState<S>,
    tx_index: TxIndex,
    block_context: &mut BlockContext,
    txs_chunk: &[Transaction],
    read_sets: &[StateMaps],
    transaction_infos: &mut [TransactionExecutionResult<TransactionExecutionInfo>],
) -> StateResult<bool> {
    let result_tx_info = &mut transaction_infos[tx_index];
    if result_tx_info.is_err() {
        return Ok(true);
    }

    let read_set = &read_sets[tx_index];
    let tx = &txs_chunk[tx_index];
    // TODO(meshi 20/05/2024): remove the redundant cached state.
    let mut cached_state = CachedState::from(versioned_state.pin_version(tx_index));
    let mut transactional_state = CachedState::create_transactional(&mut cached_state);
    let tx_versioned_state = versioned_state.pin_version(tx_index);

    if !tx_versioned_state.validate_read_set(read_set) {
        // Revalidate failed: re-execute the transaction, and commit.
        block_context.concurrency_mode = false;
        transaction_infos[tx_index] = commit_triggered_execute(
            block_context,
            tx,
            &mut transactional_state,
            &tx_versioned_state,
        );
        // Another validation after the re-execution for sanity check.
        tx_versioned_state.validate_read_set(read_set);
        // TODO(Meshi, 01/06/2024): check if this is also needed in the bouncer.
        return Ok(true);
    }
    // Revalidate succeeded
    let tx_context = Arc::new(block_context.to_tx_context(tx));
    // When the sequncer transfer fee to itself, we use the sequential fee transfer so there is no
    // need to do these fixes.
    if tx_context.tx_info.sender_address() != block_context.block_info.sequencer_address {
        let (sequencer_balance_key_low, sequencer_balance_key_high) =
            get_sequencer_balance_keys(&tx_context.block_context);
        let sequencer_balance_low = tx_versioned_state
            .get_storage_at(tx_context.fee_token_address(), sequencer_balance_key_low)?;
        let sequencer_balance_high = tx_versioned_state
            .get_storage_at(tx_context.fee_token_address(), sequencer_balance_key_high)?;

        let tx_info =
            result_tx_info.as_mut().expect("Transaction info should not be an error here.");
        if let Some(fee_transfer_call_info) = tx_info.fee_transfer_call_info.as_mut() {
            // Fix the transfer call info.
            fill_sequencer_balance_reads(
                fee_transfer_call_info,
                sequencer_balance_low,
                sequencer_balance_high,
            );

            // Update the sequencer balance in the storage.
            add_fee_to_sequencer_balance(
                tx_context,
                &tx_versioned_state,
                tx_info,
                &mut transactional_state,
            )?;
        }
    }
    // TODO(Meshi, 01/06/2024): check if this is also needed in the bouncer.
    Ok(true)
}
