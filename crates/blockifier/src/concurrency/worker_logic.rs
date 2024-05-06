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
