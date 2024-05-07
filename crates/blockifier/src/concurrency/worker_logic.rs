use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::{Arc, Mutex, MutexGuard};

use starknet_api::core::ClassHash;

use crate::concurrency::scheduler::{Scheduler, Task};
use crate::concurrency::versioned_state_proxy::ThreadSafeVersionedState;
use crate::concurrency::TxIndex;
use crate::context::BlockContext;
use crate::state::cached_state::{CachedState, StateMaps};
use crate::state::state_api::StateReader;
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::ExecutableTransaction;

pub struct ConcurrentExecutionContext<S: StateReader> {
    pub scheduler: Scheduler,
    pub state: ThreadSafeVersionedState<S>,
    pub chunk: Box<[Transaction]>,
    pub execution_outputs: Box<[Mutex<Option<ExecutionTaskOutput>>]>,
    pub block_context: BlockContext,
}

#[derive(Debug)]
pub struct ExecutionTaskOutput {
    pub reads: StateMaps,
    pub writes: StateMaps,
    pub visited_pcs: HashMap<ClassHash, HashSet<usize>>,
    pub result: TransactionExecutionResult<TransactionExecutionInfo>,
}

pub fn lock_array_of_mutex<T: Debug>(array: &[Mutex<T>], tx_index: TxIndex) -> MutexGuard<'_, T> {
    array[tx_index].lock().unwrap_or_else(|error| {
        panic!("Cell of transaction index {} is poisoned. Data: {:?}.", tx_index, *error.get_ref())
    })
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

fn execute<S: StateReader>(execution_context: &ConcurrentExecutionContext<S>, tx_index: TxIndex) {
    execute_tx(execution_context, tx_index);

    execution_context.scheduler.finish_execution(tx_index)
}

fn execute_tx<S: StateReader>(
    execution_context: &ConcurrentExecutionContext<S>,
    tx_index: TxIndex,
) {
    let ConcurrentExecutionContext { state, chunk, execution_outputs, block_context, .. } =
        &execution_context;
    let tx_versioned_state = state.pin_version(tx_index);
    let tx = &chunk[tx_index];
    // TODO(Noa, 15/05/2024): remove the redundant cached state.
    let mut tx_state = CachedState::new(tx_versioned_state);
    let mut transactional_state = CachedState::create_transactional(&mut tx_state);
    let validate = true;
    let charge_fee = true;

    let execution_result =
        tx.execute_raw(&mut transactional_state, block_context, charge_fee, validate);

    if execution_result.is_ok() {
        let class_hash_to_class = transactional_state.class_hash_to_class.borrow();
        // TODO(Noa, 15/05/2024): use `tx_versioned_state` when we add support to transactional
        // versioned state.
        state
            .pin_version(tx_index)
            .apply_writes(&transactional_state.cache.borrow().writes, &class_hash_to_class);
    }

    // Write the transaction execution outputs.
    let mut execution_output = lock_array_of_mutex(execution_outputs, tx_index);
    let tx_reads_writes = transactional_state.cache.take();
    *execution_output = Some(ExecutionTaskOutput {
        reads: tx_reads_writes.initial_reads,
        writes: tx_reads_writes.writes,
        visited_pcs: transactional_state.visited_pcs,
        result: execution_result,
    });
}

fn validate<S: StateReader>(
    _execution_context: &ConcurrentExecutionContext<S>,
    _tx_index: TxIndex,
) -> Task {
    todo!();
}
