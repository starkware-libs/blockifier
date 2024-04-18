use std::cmp::min;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::concurrency::TxIndex;

#[cfg(test)]
#[path = "scheduler_test.rs"]
pub mod test;

// TODO(Avi, 01/04/2024): Remove dead_code attribute.
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct Scheduler {
    execution_index: AtomicUsize,
    validation_index: AtomicUsize,
    /// Read twice upon checking the chunk completion. Used to detect if validation or execution
    /// index decreased from their observed values after ensuring that the number of active tasks
    /// is zero.
    decrease_counter: AtomicUsize,
    n_active_tasks: AtomicUsize,
    chunk_size: usize,
    tx_statuses: Box<[Mutex<TransactionStatus>]>,
    /// Updated by the `check_done` procedure, providing a cheap way for all threads to exit their
    /// main loops.
    done_marker: AtomicBool,
}

// TODO(Avi, 01/04/2024): Remove dead_code attribute.
#[allow(dead_code)]
impl Scheduler {
    pub fn new(chunk_size: usize) -> Scheduler {
        Scheduler {
            execution_index: AtomicUsize::new(0),
            validation_index: AtomicUsize::new(chunk_size),
            decrease_counter: AtomicUsize::new(0),
            n_active_tasks: AtomicUsize::new(0),
            chunk_size,
            tx_statuses: std::iter::repeat_with(|| Mutex::new(TransactionStatus::ReadyToExecute))
                .take(chunk_size)
                .collect(),
            done_marker: AtomicBool::new(false),
        }
    }

    /// Returns the done marker.
    pub fn done(&self) -> bool {
        self.done_marker.load(Ordering::Acquire)
    }

    /// Checks if all transactions have been executed and validated.
    fn check_done(&self) {
        let observed_decrease_counter = self.decrease_counter.load(Ordering::Acquire);

        if min(
            self.validation_index.load(Ordering::Acquire),
            self.execution_index.load(Ordering::Acquire),
        ) >= self.chunk_size
            && self.n_active_tasks.load(Ordering::Acquire) == 0
            && observed_decrease_counter == self.decrease_counter.load(Ordering::Acquire)
        {
            self.done_marker.store(true, Ordering::Release);
        }
    }

    fn safe_decrement_n_active_tasks(&self) {
        let previous_n_active_tasks = self.n_active_tasks.fetch_sub(1, Ordering::SeqCst);
        assert!(previous_n_active_tasks > 0, "n_active_tasks underflow");
    }

    pub fn next_task(&self) -> Task {
        if self.done() {
            return Task::Done;
        }

        let index_to_validate = self.validation_index.load(Ordering::Acquire);
        let index_to_execute = self.execution_index.load(Ordering::Acquire);

        if min(index_to_validate, index_to_execute) >= self.chunk_size {
            return Task::NoTask;
        }

        if index_to_validate < index_to_execute {
            if let Some(tx_index) = self.next_version_to_validate() {
                return Task::ValidationTask(tx_index);
            }
        }

        if let Some(tx_index) = self.next_version_to_execute() {
            return Task::ExecutionTask(tx_index);
        }

        Task::NoTask
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

    fn decrease_validation_index(&self, target_index: TxIndex) {
        let previous_validation_index =
            self.validation_index.fetch_min(target_index, Ordering::SeqCst);
        if target_index < previous_validation_index {
            self.decrease_counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn decrease_execution_index(&self, target_index: TxIndex) {
        let previous_execution_index =
            self.execution_index.fetch_min(target_index, Ordering::SeqCst);
        if target_index < previous_execution_index {
            self.decrease_counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Updates a transaction's status to `Executing` if it is ready to execute.
    fn try_incarnate(&self, tx_index: TxIndex) -> Option<TxIndex> {
        if tx_index < self.chunk_size {
            // TODO(barak, 01/04/2024): complete try_incarnate logic.
            return Some(tx_index);
        }
        self.safe_decrement_n_active_tasks();
        None
    }

    fn next_version_to_validate(&self) -> Option<TxIndex> {
        let index_to_validate = self.validation_index.load(Ordering::Acquire);
        if index_to_validate >= self.chunk_size {
            self.check_done();
            return None;
        }
        self.n_active_tasks.fetch_add(1, Ordering::SeqCst);
        let index_to_validate = self.validation_index.fetch_add(1, Ordering::SeqCst);
        if index_to_validate < self.chunk_size {
            // TODO(barak, 01/04/2024): complete next_version_to_validate logic.
            return Some(index_to_validate);
        }
        self.safe_decrement_n_active_tasks();
        None
    }

    fn next_version_to_execute(&self) -> Option<TxIndex> {
        let index_to_execute = self.execution_index.load(Ordering::Acquire);
        if index_to_execute >= self.chunk_size {
            self.check_done();
            return None;
        }
        self.n_active_tasks.fetch_add(1, Ordering::SeqCst);
        let index_to_execute = self.execution_index.fetch_add(1, Ordering::SeqCst);
        self.try_incarnate(index_to_execute)
    }
}

#[derive(Debug, PartialEq)]
pub enum Task {
    ExecutionTask(TxIndex),
    ValidationTask(TxIndex),
    NoTask,
    Done,
}

// TODO(Barak, 01/04/2024): Remove dead_code attribute.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum TransactionStatus {
    ReadyToExecute,
    Executing,
    Executed,
    Aborting,
}
