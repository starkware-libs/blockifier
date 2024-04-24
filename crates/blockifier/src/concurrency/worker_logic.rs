use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::transaction::Fee;

use super::versioned_state_proxy::VersionedStateProxy;
use crate::concurrency::fee_utils::fill_sequencer_balance_reads;
use crate::concurrency::scheduler::{Scheduler, Task};
use crate::concurrency::versioned_state_proxy::ThreadSafeVersionedState;
use crate::concurrency::TxIndex;
use crate::context::BlockContext;
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::state::cached_state::{CachedState, StateMaps};
use crate::state::state_api::{StateReader, StateResult};
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transaction_execution::Transaction;

pub struct ConcurrentExecutionContext<S: StateReader> {
    pub scheduler: Scheduler,
    pub state: ThreadSafeVersionedState<S>,
    pub chunk: Box<[Transaction]>,
    pub execution_outputs: Box<[Mutex<ExecutionTaskOutput>]>,
    pub block_context: BlockContext,
}

pub struct ExecutionTaskOutput {
    pub reads: StateMaps,
    pub writes: StateMaps,
    pub visited_pcs: HashMap<ClassHash, HashSet<usize>>,
    pub result: TransactionExecutionResult<TransactionExecutionInfo>,
}

// TODO(Noa, 15/05/2024): Re-consider the necessity of the Arc (as opposed to a reference), given
// concurrent code.
pub fn run<S: StateReader>(execution_context: Arc<ConcurrentExecutionContext<S>>) {
    let scheduler = &execution_context.scheduler;
    let mut task = Task::NoTask;
    loop {
        task = match task {
            Task::ExecutionTask(tx_index) => {
                execute(&execution_context, tx_index);
                Task::NoTask
            }
            Task::ValidationTask(tx_index) => validate(&execution_context, tx_index),
            Task::NoTask => scheduler.next_task(),
            Task::Done => break,
        };
    }
}

fn execute<S: StateReader>(_execution_context: &ConcurrentExecutionContext<S>, _tx_index: TxIndex) {
    // TODO(Noa, 15/05/2024): share code with `try_commit`.
    todo!();
}

fn validate<S: StateReader>(
    _execution_context: &ConcurrentExecutionContext<S>,
    _tx_index: TxIndex,
) -> Task {
    todo!();
}

fn finalize_commit(
    _fee_token_address: ContractAddress,
    _tx_versioned_state: &VersionedStateProxy<impl StateReader>,
    _actual_fee: &Fee,
    _transactional_state: &mut CachedState<impl StateReader>,
) -> StateResult<()> {
    todo!()
}

pub fn try_commit_transaction<S: StateReader>(
    execution_context: &ConcurrentExecutionContext<S>,
    tx_index: TxIndex,
    // versioned_state: &mut ThreadSafeVersionedState<S>,

    // block_context: &mut BlockContext,
    // txs_chunk: &[Transaction],
    // read_sets: &[StateMaps],
    // transaction_infos: &mut [TransactionExecutionResult<TransactionExecutionInfo>],
) -> StateResult<bool> {
    let ConcurrentExecutionContext {
        scheduler: _,
        state: versioned_state,
        chunk: txs_chunk,
        execution_outputs,
        block_context,
    } = execution_context;
    let result_tx_info = &mut execution_outputs[tx_index].lock().unwrap().result;
    drop(execution_outputs);
    let read_set = &execution_outputs[tx_index].lock().unwrap().reads;
    drop(execution_outputs);
    let tx = &txs_chunk[tx_index];
    // TODO(meshi 20/05/2024): remove the redundant cached state.
    let mut cached_state = CachedState::from(versioned_state.pin_version(tx_index));
    let mut transactional_state = CachedState::create_transactional(&mut cached_state);
    let tx_versioned_state = versioned_state.pin_version(tx_index);

    // First, re-validate the transaction.
    if !tx_versioned_state.validate_read_set(read_set) {
        // Revalidate failed: re-execute the transaction, and commit.
        let new_execution_context = ConcurrentExecutionContext {
            block_context: BlockContext{concurrency_mode: false, ..block_context.clone()},
            .. execution_context.clone()
        };
        execute(&new_execution_context, tx_index);
        let result_tx_info = &mut execution_outputs[tx_index].lock().unwrap().result;
        drop(execution_outputs);
        if result_tx_info.is_err() {
            // TODO(Meshi, 01/06/2024): Rvert the chanches of the execution before the re-execution.
            todo!()
        }
        // Another validation after the re-execution for sanity check.
        assert!(tx_versioned_state.validate_read_set(read_set));
        // TODO(Meshi, 01/06/2024): check if this is also needed in the bouncer.
        return Ok(true);
    }
    // Revalidate succeeded.
    if result_tx_info.is_err() {
        return Ok(true);
    }
    let tx_context = Arc::new(block_context.to_tx_context(tx));
    // Fix the sequencer balance.
    // There is no need to fix the balance when the sequencer transfers fee to itself, since we use the sequential fee transfer in this case.
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
            finalize_commit(
                tx_context.fee_token_address(),
                &tx_versioned_state,
                &tx_info.actual_fee,
                &mut transactional_state,
            )?;
        }
    }
    // TODO(Meshi, 01/06/2024): check if this is also needed in the bouncer.
    Ok(true)
}
