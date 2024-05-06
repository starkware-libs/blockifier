use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use starknet_api::core::ClassHash;

use crate::concurrency::scheduler::{Scheduler, Task};
use crate::concurrency::versioned_state_proxy::ThreadSafeVersionedState;
use crate::concurrency::TxIndex;
use crate::context::BlockContext;
use crate::state::cached_state::StateMaps;
use crate::state::state_api::StateReader;
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transaction_execution::Transaction;

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
    _scheduler: &Scheduler,
    _tx_index: TxIndex,
    _state: &ThreadSafeVersionedState<S>,
    _chunk: &[Transaction],
    _execution_outputs: &[Mutex<ExecutionTaskOutput>],
    _block_context: &BlockContext,
) {
    // TODO(Noa, 15/05/2024): share code with `try_commit`.
    todo!();
}

fn validate<S: StateReader>(
    _scheduler: &Scheduler,
    _tx_index: TxIndex,
    _state: &ThreadSafeVersionedState<S>,
    _execution_outputs: &[Mutex<ExecutionTaskOutput>],
) -> Task {
    todo!();
}
