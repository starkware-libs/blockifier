use std::sync::Arc;

use cached::async_sync::Mutex;

use super::versioned_state_proxy::TxInputOutput;
use crate::concurrency::scheduler::{Scheduler, Task};
use crate::concurrency::versioned_state_proxy::ThreadSafeVersionedState;
use crate::concurrency::TxIndex;
use crate::context::BlockContext;
use crate::state::state_api::StateReader;
use crate::transaction::transaction_execution::Transaction;

// TODO(Noa, 15/05/2024): Consider making it a method of (concurrent) transaction executor.
// TODO(Noa, 15/05/2024): Consider defining a concurrent executor with the input parameters as
// fields.
pub fn run<S: StateReader>(
    scheduler: Arc<Scheduler>,
    state: ThreadSafeVersionedState<S>,
    chunk: &[Transaction],
    tx_input_output: &[Mutex<TxInputOutput>],
    block_context: &BlockContext,
) {
    let mut task = Task::NoTask;
    loop {
        task = match task {
            Task::ExecutionTask(tx_index) => {
                execute(&scheduler, tx_index, &state, chunk, tx_input_output, block_context)
            }
            Task::ValidationTask(tx_index) => {
                validate(&scheduler, tx_index, &state, tx_input_output)
            }
            Task::NoTask => scheduler.next_task(),
            Task::Done => todo!(),
        };
    }
}

fn execute<S: StateReader>(
    _scheduler: &Scheduler,
    _tx_index: TxIndex,
    _state: &ThreadSafeVersionedState<S>,
    _chunk: &[Transaction],
    _tx_input_output: &[Mutex<TxInputOutput>],
    _block_context: &BlockContext,
) -> Task {
    // TODO(Noa, 15/05/2024): share code with `try_commit`.
    todo!();
}

fn validate<S: StateReader>(
    _scheduler: &Scheduler,
    _tx_index: TxIndex,
    _state: &ThreadSafeVersionedState<S>,
    _tx_input_output: &[Mutex<TxInputOutput>],
) -> Task {
    todo!();
}
