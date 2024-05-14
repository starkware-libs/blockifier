use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::Mutex;

use starknet_api::core::ClassHash;

use crate::concurrency::scheduler::{Scheduler, Task};
use crate::concurrency::utils::lock_mutex_in_array;
use crate::concurrency::versioned_state_proxy::ThreadSafeVersionedState;
use crate::concurrency::TxIndex;
use crate::context::BlockContext;
use crate::state::cached_state::{CachedState, StateMaps};
use crate::state::state_api::StateReader;
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::ExecutableTransaction;

#[derive(Debug)]
pub struct ExecutionTaskOutput {
    pub reads: StateMaps,
    pub writes: StateMaps,
    pub visited_pcs: HashMap<ClassHash, HashSet<usize>>,
    pub result: TransactionExecutionResult<TransactionExecutionInfo>,
}

pub struct WorkerExecutor<'a, S: StateReader> {
    pub scheduler: Scheduler,
    pub state: ThreadSafeVersionedState<S>,
    pub chunk: &'a [Transaction],
    pub execution_outputs: Box<[Mutex<Option<ExecutionTaskOutput>>]>,
    pub block_context: BlockContext,
}
impl<'a, S: StateReader> WorkerExecutor<'a, S> {
    pub fn new(
        scheduler: Scheduler,
        state: ThreadSafeVersionedState<S>,
        chunk: &'a [Transaction],
        block_context: BlockContext,
    ) -> Self {
        let execution_outputs =
            std::iter::repeat_with(|| Mutex::new(None)).take(scheduler.chunk_size).collect();

        WorkerExecutor { scheduler, state, chunk, execution_outputs, block_context }
    }

    pub fn run(&self) {
        let mut task = Task::NoTask;
        loop {
            task = match task {
                Task::ExecutionTask(tx_index) => {
                    self.execute(tx_index);
                    Task::NoTask
                }
                Task::ValidationTask(tx_index) => self.validate(tx_index),
                Task::NoTask => self.scheduler.next_task(),
                Task::Done => break,
            };
        }
    }

    fn execute(&self, tx_index: TxIndex) {
        self.execute_tx(tx_index);
        self.scheduler.finish_execution(tx_index)
    }

    fn execute_tx(&self, tx_index: TxIndex) {
        let tx_versioned_state = self.state.pin_version(tx_index);
        let tx = &self.chunk[tx_index];
        // TODO(Noa, 15/05/2024): remove the redundant cached state.
        let mut tx_state = CachedState::new(tx_versioned_state);
        let mut transactional_state = CachedState::create_transactional(&mut tx_state);
        let validate = true;
        let charge_fee = true;

        let execution_result =
            tx.execute_raw(&mut transactional_state, &self.block_context, charge_fee, validate);

        if execution_result.is_ok() {
            let class_hash_to_class = transactional_state.class_hash_to_class.borrow();
            // TODO(Noa, 15/05/2024): use `tx_versioned_state` when we add support to transactional
            // versioned state.
            self.state
                .pin_version(tx_index)
                .apply_writes(&transactional_state.cache.borrow().writes, &class_hash_to_class);
        }

        // Write the transaction execution outputs.
        let tx_reads_writes = transactional_state.cache.take();
        // In case of a failed transaction, we don't record its writes and visited pcs.
        let (writes, visited_pcs) = match execution_result {
            Ok(_) => (tx_reads_writes.writes, transactional_state.visited_pcs),
            Err(_) => (StateMaps::default(), HashMap::default()),
        };
        let mut execution_output = lock_mutex_in_array(&self.execution_outputs, tx_index);
        *execution_output = Some(ExecutionTaskOutput {
            reads: tx_reads_writes.initial_reads,
            writes,
            visited_pcs,
            result: execution_result,
        });
    }

    fn validate(&self, _tx_index: TxIndex) -> Task {
        todo!();
    }
}
