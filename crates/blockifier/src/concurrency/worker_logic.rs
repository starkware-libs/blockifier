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

pub fn lock_array_of_mutex<T: Debug>(array: &[Mutex<T>], tx_index: TxIndex) -> MutexGuard<'_, T> {
    array[tx_index].lock().unwrap_or_else(|error| {
        panic!("Cell of transaction index {} is poisoned. Data: {:?}.", tx_index, *error.get_ref())
    })
}

#[derive(Debug)]
pub struct ExecutionTaskOutput {
    pub reads: StateMaps,
    pub writes: StateMaps,
    pub visited_pcs: HashMap<ClassHash, HashSet<usize>>,
    pub result: TransactionExecutionResult<TransactionExecutionInfo>,
}

// TODO(Noa, 15/05/2024): Consider making it a method of (concurrent) transaction executor.
// TODO(Noa, 15/05/2024): Consider defining a concurrent executor with the input parameters as
// fields.
pub fn run<S: StateReader>(
    scheduler: Arc<Scheduler>,
    state: ThreadSafeVersionedState<S>,
    chunk: &[Transaction],
    execution_outputs: &[Mutex<ExecutionTaskOutput>],
    block_context: &BlockContext,
) {
    let mut task = Task::NoTask;
    loop {
        task = match task {
            Task::ExecutionTask(tx_index) => {
                execute(&scheduler, tx_index, &state, chunk, execution_outputs, block_context);
                scheduler.next_task()
            }
            Task::ValidationTask(tx_index) => {
                validate(&scheduler, tx_index, &state, execution_outputs)
            }
            Task::NoTask => scheduler.next_task(),
            Task::Done => break,
        };
    }
}

fn execute<S: StateReader>(
    scheduler: &Scheduler,
    tx_index: TxIndex,
    state: &ThreadSafeVersionedState<S>,
    chunk: &[Transaction],
    execution_outputs: &[Mutex<ExecutionTaskOutput>],
    block_context: &BlockContext,
) {
    // TODO(Noa, 15/05/2024): share code with `try_commit`.
    let tx_versioned_state = state.pin_version(tx_index);
    let tx = &chunk[tx_index];
    // TODO(Noa, 15/05/2024): remove the redundant cached state.
    let mut tx_state = CachedState::new(tx_versioned_state);
    let mut transactional_state = CachedState::create_transactional(&mut tx_state);
    let validate = true;
    let charge_fee = true;

    let execution_result =
        tx.execute_raw(&mut transactional_state, block_context, charge_fee, validate);
    let mut execution_output = lock_array_of_mutex(execution_outputs, tx_index);

    // Write the transaction execution outputs.
    execution_output.result = execution_result;
    let tx_reads_writes = transactional_state.cache.take();
    execution_output.reads = tx_reads_writes.initial_reads;
    execution_output.writes = tx_reads_writes.writes;
    execution_output.visited_pcs = transactional_state.visited_pcs;

    if execution_output.result.is_ok() {
        let class_hash_to_class = transactional_state.class_hash_to_class.borrow();
        // TODO(Noa, 15/05/2024): use `tx_versioned_state` when we add support to transactional
        // versioned state.
        state.pin_version(tx_index).apply_writes(&execution_output.writes, &class_hash_to_class);
    }

    scheduler.finish_execution(tx_index)
}

fn validate<S: StateReader>(
    _scheduler: &Scheduler,
    _tx_index: TxIndex,
    _state: &ThreadSafeVersionedState<S>,
    _execution_outputs: &[Mutex<ExecutionTaskOutput>],
) -> Task {
    todo!();
}
