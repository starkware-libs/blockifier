use std::sync::Arc;

use super::versioned_state_proxy::{ThreadSafeVersionedState, VersionedStateProxy};
use super::TxIndex;
use crate::concurrency::fee_utils::fill_sequencer_balance_reads;
use crate::context::BlockContext;
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::state::cached_state::{CachedState, StateMaps, TransactionalState};
use crate::state::state_api::{StateReader, StateResult};
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::ExecutableTransaction;

pub fn commit_triggered_execute(
    block_context: &mut BlockContext,
    tx: &Transaction,
    transactional_state: &mut TransactionalState<'_, impl StateReader>,
    pinned_versioned_state: VersionedStateProxy<impl StateReader>,
) -> TransactionExecutionResult<TransactionExecutionInfo> {
    let charge_fee = true;
    let validete = true;
    block_context.concurrency_mode = false;
    let execution_result = tx.execute_raw(transactional_state, block_context, charge_fee, validete);
    if execution_result.is_ok() {
        // TODO(Avi, 20/5/2024): Add finish_execution_during_commit to the scheduler and use it
        // here.
        pinned_versioned_state.apply_writes(
            &transactional_state.cache.borrow().writes,
            &transactional_state.class_hash_to_class.borrow(),
        );
    }
    execution_result
}


