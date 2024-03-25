use std::cmp::min;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::concurrency::Version;

#[cfg(test)]
#[path = "scheduler_test.rs"]
pub mod test;

#[derive(Default)]
pub struct Scheduler {
    // The index of the next transaction to be executed.
    pub execution_idx: AtomicU32,
    // The index of the next transaction to be validated.
    pub validation_idx: AtomicU32,
    // The number of times the scheduler has decreased the execution/validation index.
    pub decrease_counter: AtomicU32,
    // The number of active tasks.
    pub n_active_tasks: AtomicU32,
    // The number of transactions in each chunk.
    pub chunk_size: u32,
    // A marker indicating that all transactions have been executed and validated.
    pub done_marker: AtomicBool,
}

impl Scheduler {
    pub fn new(chunk_size: u32) -> Scheduler {
        Scheduler { chunk_size, ..Default::default() }
    }

    // Returns the done marker.
    pub fn done(&self) -> bool {
        self.done_marker.load(Ordering::Acquire)
    }

    // Checks if all transactions have been executed and validated. Namely, if both the execution
    // and validation indexes are at least the chunk size, and there are no active tasks.
    pub fn check_done(&self) {
        let observed_decrease_counter = self.decrease_counter.load(Ordering::Acquire);
        let validation_idx = self.validation_idx.load(Ordering::Acquire);
        let execution_idx = self.execution_idx.load(Ordering::Acquire);
        let n_active_tasks = self.n_active_tasks.load(Ordering::Acquire);

        if min(validation_idx, execution_idx) >= self.chunk_size
            && n_active_tasks == 0
            && observed_decrease_counter == self.decrease_counter.load(Ordering::Acquire)
        {
            self.done_marker.store(true, Ordering::Release);
        }
    }

    /// Returns the next task to run. Prioritizes validation tasks.
    pub fn next_task(&self) -> Task {
        loop {
            if self.done() {
                return Task::Done;
            }

            let idx_to_validate = self.validation_idx.load(Ordering::Acquire);
            let idx_to_execute = self.execution_idx.load(Ordering::Acquire);

            if min(idx_to_validate, idx_to_execute) >= self.chunk_size {
                return Task::NoTask;
            }

            if idx_to_validate < idx_to_execute {
                if let Some(tx_idx) = self.next_version_to_validate() {
                    return Task::ValidationTask(tx_idx.into());
                }
            }
            if let Some(tx_idx) = self.next_version_to_execute() {
                return Task::ExecutionTask(tx_idx.into());
            }
        }
    }

    // TODO(barak, 01/04/2024): Ensure documentation matches logic.
    /// Updates the Scheduler that an execution task has been finished and triggers the creation of
    /// new tasks accordingly: schedules validation for the current and higher transactions, if not
    /// already scheduled.
    pub fn finish_execution(&self) -> Task {
        todo!()
    }

    // TODO(barak, 01/04/2024): Ensure documentation matches logic.
    /// Updates the Scheduler that a validation task has been finished and triggers the creation of
    /// new tasks in case of failure: schedules validation for higher transactions + re-executes the
    /// current transaction (if ready).
    pub fn finish_validation(&self) -> Task {
        todo!()
    }

    // Decreases the validation index to the target index if the target index is lower than the
    // current validation index.
    pub fn decrease_validation_idx(&self, target_idx: u32) {
        self.validation_idx.fetch_min(target_idx, Ordering::SeqCst);
        self.decrease_counter.fetch_add(1, Ordering::SeqCst);
    }

    // Decreases the execution index to the target index if the target index is lower than the
    // current execution index.
    pub fn decrease_execution_idx(&self, target_idx: u32) {
        self.execution_idx.fetch_min(target_idx, Ordering::SeqCst);
        self.decrease_counter.fetch_add(1, Ordering::SeqCst);
    }

    // Tries to schedule the execution of a transaction. If the transaction is not ready to execute,
    // the number of active tasks is decreased and the function returns None.
    pub fn try_schedule_execute(&self, tx_idx: u32) -> Option<u32> {
        if tx_idx < self.chunk_size {
            // TODO(barak, 01/04/2024): implement tx_status and add the following two lines:
            // if tx_status == TxStatus::ReadyToExecute
            //     tx_status = TxStatus::Executing
            return Some(tx_idx);
        }
        self.n_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    // Returns the next version to validate if there is one, otherwise returns None.
    pub fn next_version_to_validate(&self) -> Option<u32> {
        let idx_to_validate = self.validation_idx.load(Ordering::Acquire);
        if idx_to_validate >= self.chunk_size {
            self.check_done();
            return None;
        }
        self.n_active_tasks.fetch_add(1, Ordering::SeqCst);
        let idx_to_validate = self.validation_idx.fetch_add(1, Ordering::SeqCst);
        if idx_to_validate < self.chunk_size {
            // TODO(barak, 01/04/2024): implement tx_status and add the following condition:
            // if tx_status == TxStatus::Executed
            return Some(idx_to_validate);
        }
        self.n_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    // Returns the next version to execute if there is one, otherwise returns None.
    pub fn next_version_to_execute(&self) -> Option<u32> {
        let idx_to_execute = self.execution_idx.load(Ordering::Acquire);
        if idx_to_execute >= self.chunk_size {
            self.check_done();
            return None;
        }
        self.n_active_tasks.fetch_add(1, Ordering::SeqCst);
        let idx_to_execute = self.execution_idx.fetch_add(1, Ordering::SeqCst);
        self.try_schedule_execute(idx_to_execute)
    }
}

pub enum Task {
    ExecutionTask(Version),
    ValidationTask(Version),
    NoTask,
    Done,
}
