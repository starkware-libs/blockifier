use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use starknet_api::core::ClassHash;

use super::versioned_state::VersionedState;
use crate::blockifier::transaction_executor::TransactionExecutorError;
use crate::bouncer::Bouncer;
use crate::concurrency::fee_utils::complete_fee_transfer_flow;
use crate::concurrency::scheduler::{Scheduler, Task};
use crate::concurrency::utils::lock_mutex_in_array;
use crate::concurrency::versioned_state::ThreadSafeVersionedState;
use crate::concurrency::TxIndex;
use crate::context::BlockContext;
use crate::state::cached_state::{
    ContractClassMapping, StateChanges, StateMaps, TransactionalState,
};
use crate::state::state_api::{StateReader, UpdatableState};
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::{ExecutableTransaction, ExecutionFlags};

#[cfg(test)]
#[path = "worker_logic_test.rs"]
pub mod test;

const EXECUTION_OUTPUTS_UNWRAP_ERROR: &str = "Execution task outputs should not be None.";

#[derive(Debug)]
pub struct ExecutionTaskOutput {
    pub reads: StateMaps,
    pub writes: StateMaps,
    pub contract_classes: ContractClassMapping,
    pub visited_pcs: HashMap<ClassHash, HashSet<usize>>,
    pub result: TransactionExecutionResult<TransactionExecutionInfo>,
}

pub struct WorkerExecutor<'a, S: StateReader> {
    pub scheduler: Scheduler,
    pub state: ThreadSafeVersionedState<S>,
    pub chunk: &'a [Transaction],
    pub execution_outputs: Box<[Mutex<Option<ExecutionTaskOutput>>]>,
    pub block_context: &'a BlockContext,
    pub bouncer: Mutex<&'a mut Bouncer>,
}
impl<'a, S: StateReader> WorkerExecutor<'a, S> {
    pub fn new(
        state: ThreadSafeVersionedState<S>,
        chunk: &'a [Transaction],
        block_context: &'a BlockContext,
        bouncer: Mutex<&'a mut Bouncer>,
    ) -> Self {
        let scheduler = Scheduler::new(chunk.len());
        let execution_outputs =
            std::iter::repeat_with(|| Mutex::new(None)).take(chunk.len()).collect();

        WorkerExecutor { scheduler, state, chunk, execution_outputs, block_context, bouncer }
    }

    // TODO(barak, 01/08/2024): Remove the `new` method or move it to test utils.
    pub fn initialize(
        state: S,
        chunk: &'a [Transaction],
        block_context: &'a BlockContext,
        bouncer: Mutex<&'a mut Bouncer>,
    ) -> Self {
        let versioned_state = VersionedState::new(state);
        let chunk_state = ThreadSafeVersionedState::new(versioned_state);
        let scheduler = Scheduler::new(chunk.len());
        let execution_outputs =
            std::iter::repeat_with(|| Mutex::new(None)).take(chunk.len()).collect();

        WorkerExecutor {
            scheduler,
            state: chunk_state,
            chunk,
            execution_outputs,
            block_context,
            bouncer,
        }
    }

    pub fn run(&self) {
        let mut task = Task::AskForTask;
        loop {
            self.commit_while_possible();
            task = match task {
                Task::ExecutionTask(tx_index) => {
                    self.execute(tx_index);
                    Task::AskForTask
                }
                Task::ValidationTask(tx_index) => self.validate(tx_index),
                Task::NoTaskAvailable => {
                    // There's no available task at the moment; sleep for a bit to save CPU power.
                    // (since busy-looping might damage performance when using hyper-threads).
                    thread::sleep(Duration::from_micros(1));
                    Task::AskForTask
                }
                Task::AskForTask => self.scheduler.next_task(),
                Task::Done => break,
            };
        }
    }

    fn commit_while_possible(&self) {
        if let Some(mut transaction_committer) = self.scheduler.try_enter_commit_phase() {
            while let Some(tx_index) = transaction_committer.try_commit() {
                let commit_succeeded = self.commit_tx(tx_index);
                if !commit_succeeded {
                    transaction_committer.halt_scheduler();
                }
            }
        }
    }

    fn execute(&self, tx_index: TxIndex) {
        self.execute_tx(tx_index);
        self.scheduler.finish_execution(tx_index)
    }

    fn execute_tx(&self, tx_index: TxIndex) {
        let mut tx_versioned_state = self.state.pin_version(tx_index);
        let tx = &self.chunk[tx_index];
        let mut transactional_state =
            TransactionalState::create_transactional(&mut tx_versioned_state);
        let execution_flags =
            ExecutionFlags { charge_fee: true, validate: true, concurrency_mode: true };
        let execution_result =
            tx.execute_raw(&mut transactional_state, self.block_context, execution_flags);

        if execution_result.is_ok() {
            // TODO(Noa, 15/05/2024): use `tx_versioned_state` when we add support to transactional
            // versioned state.
            self.state.pin_version(tx_index).apply_writes(
                &transactional_state.cache.borrow().writes,
                &transactional_state.class_hash_to_class.borrow(),
                &HashMap::default(),
            );
        }

        // Write the transaction execution outputs.
        let tx_reads_writes = transactional_state.cache.take();
        let class_hash_to_class = transactional_state.class_hash_to_class.take();
        // In case of a failed transaction, we don't record its writes and visited pcs.
        let (writes, contract_classes, visited_pcs) = match execution_result {
            Ok(_) => (tx_reads_writes.writes, class_hash_to_class, transactional_state.visited_pcs),
            Err(_) => (StateMaps::default(), HashMap::default(), HashMap::default()),
        };
        let mut execution_output = lock_mutex_in_array(&self.execution_outputs, tx_index);
        *execution_output = Some(ExecutionTaskOutput {
            reads: tx_reads_writes.initial_reads,
            writes,
            contract_classes,
            visited_pcs,
            result: execution_result,
        });
    }

    fn validate(&self, tx_index: TxIndex) -> Task {
        let tx_versioned_state = self.state.pin_version(tx_index);
        let execution_output = lock_mutex_in_array(&self.execution_outputs, tx_index);
        let execution_output = execution_output.as_ref().expect(EXECUTION_OUTPUTS_UNWRAP_ERROR);
        let reads = &execution_output.reads;
        let reads_valid = tx_versioned_state.validate_reads(reads);

        let aborted = !reads_valid && self.scheduler.try_validation_abort(tx_index);
        if aborted {
            tx_versioned_state
                .delete_writes(&execution_output.writes, &execution_output.contract_classes);
            self.scheduler.finish_abort(tx_index)
        } else {
            Task::AskForTask
        }
    }

    /// Commits a transaction. The commit process is as follows:
    /// 1) Validate the read set.
    ///     * If validation failed, delete the transaction writes and (re-)execute it.
    ///     * Else (validation succeeded), no need to re-execute.
    /// 2) Execution is final.
    ///     * If execution succeeded, ask the bouncer if there is room for the transaction in the
    ///       block.
    ///         - If there is room, fix the call info, update the sequencer balance and commit the
    ///           transaction.
    ///         - Else (no room), do not commit. The block should be closed without the transaction.
    ///     * Else (execution failed), commit the transaction without fixing the call info or
    ///       updating the sequencer balance.
    fn commit_tx(&self, tx_index: TxIndex) -> bool {
        let execution_output = lock_mutex_in_array(&self.execution_outputs, tx_index);
        let execution_output_ref = execution_output.as_ref().expect(EXECUTION_OUTPUTS_UNWRAP_ERROR);
        let reads = &execution_output_ref.reads;

        let mut tx_versioned_state = self.state.pin_version(tx_index);
        let reads_valid = tx_versioned_state.validate_reads(reads);

        // First, re-validate the transaction.
        if !reads_valid {
            // Revalidate failed: re-execute the transaction.
            tx_versioned_state.delete_writes(
                &execution_output_ref.writes,
                &execution_output_ref.contract_classes,
            );
            // Release the execution output lock as it is acquired in execution (avoid dead-lock).
            drop(execution_output);

            self.execute_tx(tx_index);
            self.scheduler.finish_execution_during_commit(tx_index);

            let execution_output = lock_mutex_in_array(&self.execution_outputs, tx_index);
            let read_set = &execution_output.as_ref().expect(EXECUTION_OUTPUTS_UNWRAP_ERROR).reads;
            // Another validation after the re-execution for sanity check.
            assert!(tx_versioned_state.validate_reads(read_set));
        } else {
            // Release the execution output lock, since it is has been released in the other flow.
            drop(execution_output);
        }

        // Execution is final.
        let mut execution_output = lock_mutex_in_array(&self.execution_outputs, tx_index);
        let writes = &execution_output.as_ref().expect(EXECUTION_OUTPUTS_UNWRAP_ERROR).writes;
        let reads = &execution_output.as_ref().expect(EXECUTION_OUTPUTS_UNWRAP_ERROR).reads;
        let mut tx_state_changes_keys = StateChanges::from(writes.diff(reads)).into_keys();
        let tx_result =
            &mut execution_output.as_mut().expect(EXECUTION_OUTPUTS_UNWRAP_ERROR).result;

        if let Ok(tx_execution_info) = tx_result.as_mut() {
            let tx_context = self.block_context.to_tx_context(&self.chunk[tx_index]);
            // Add the deleted sequencer balance key to the storage keys.
            let concurrency_mode = true;
            tx_state_changes_keys.update_sequencer_key_in_storage(
                &tx_context,
                tx_execution_info,
                concurrency_mode,
            );
            // Ask the bouncer if there is room for the transaction in the block.
            let bouncer_result = self.bouncer.lock().expect("Bouncer lock failed.").try_update(
                &tx_versioned_state,
                &tx_state_changes_keys,
                &tx_execution_info.summarize(),
                &tx_execution_info.transaction_receipt.resources,
            );
            if let Err(error) = bouncer_result {
                match error {
                    TransactionExecutorError::BlockFull => return false,
                    _ => {
                        // TODO(Avi, 01/07/2024): Consider propagating the error.
                        panic!("Bouncer update failed. {error:?}: {error}");
                    }
                }
            }
            complete_fee_transfer_flow(&tx_context, tx_execution_info, &mut tx_versioned_state);
            // Optimization: changing the sequencer balance storage cell does not trigger
            // (re-)validation of the next transactions.
        }

        true
    }
}

impl<'a, U: UpdatableState> WorkerExecutor<'a, U> {
    pub fn commit_chunk_and_recover_block_state(
        self,
        n_committed_txs: usize,
        visited_pcs: HashMap<ClassHash, HashSet<usize>>,
    ) -> U {
        self.state
            .into_inner_state()
            .commit_chunk_and_recover_block_state(n_committed_txs, visited_pcs)
    }
}
