use std::sync::Arc;

use crate::concurrency::scheduler::{Scheduler, Task};
use crate::concurrency::versioned_state_proxy::{ReadsWrites, ThreadSafeVersionedState};
use crate::concurrency::TxIndex;
use crate::context::BlockContext;
use crate::state::state_api::StateReader;
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::ExecutableTransaction;

// TODO(Noa, 15/05/2024): Consider making it a method of (concurrent) transaction executor.
// TODO(Noa, 15/05/2024): Consider defining a concurrent executor with the input parameters as
// fields.
pub fn run<S: StateReader>(
    scheduler: Arc<Scheduler>,
    state: ThreadSafeVersionedState<S>,
    chunk: &[Transaction],
    tx_results: &mut [TransactionExecutionResult<TransactionExecutionInfo>],
    reads_writes: &mut [ReadsWrites],
    block_context: &BlockContext,
) {
    let mut task = Task::NoTask;
    loop {
        task = match task {
            Task::ExecutionTask(tx_index) => try_execute(
                &scheduler,
                tx_index,
                &state,
                chunk,
                tx_results,
                reads_writes,
                block_context,
            ),
            Task::ValidationTask(tx_index) => {
                needs_reexecution(&scheduler, tx_index, &state, reads_writes)
            }
            Task::NoTask => scheduler.next_task(),
            Task::Done => todo!(),
        };
    }
}

fn try_execute<S: StateReader>(
    _scheduler: &Scheduler,
    _tx_index: TxIndex,
    _state: &ThreadSafeVersionedState<S>,
    _chunk: &[Transaction],
    _tx_results: &mut [TransactionExecutionResult<TransactionExecutionInfo>],
    _reads_writes: &mut [ReadsWrites],
    _block_context: &BlockContext,
) -> Task {
    // TODO(Noa, 15/05/2024): share code with `try_commit`.
    todo!();
}

fn needs_reexecution<S: StateReader>(
    _scheduler: &Scheduler,
    _tx_index: TxIndex,
    _state: &ThreadSafeVersionedState<S>,
    _reads_writes: &mut [ReadsWrites],
) -> Task {
    todo!();
}
