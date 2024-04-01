use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::concurrency::TxIndex;

#[cfg(test)]
#[path = "scheduler_test.rs"]
pub mod test;

// TODO(Avi, 01/04/2024): Remove dead_code attribute.
#[allow(dead_code)]
pub struct Scheduler {
    execution_index: AtomicUsize,
    validation_index: AtomicUsize,
    /// Read twice upon checking the chunk completion. Used to detect if validation or execution
    /// index decreased from their observed values after ensuring that the number of active tasks
    /// is zero.
    decrease_counter: AtomicUsize,
    n_active_tasks: AtomicUsize,
    tx_statuses: Box<[Mutex<TransactionStatus>]>,
}

// TODO(Avi, 01/04/2024): Remove dead_code attribute.
#[allow(dead_code)]
impl Scheduler {
    pub fn new(chunk_size: usize) -> Scheduler {
        Scheduler {
            execution_index: AtomicUsize::default(),
            validation_index: chunk_size.into(),
            decrease_counter: AtomicUsize::default(),
            n_active_tasks: AtomicUsize::default(),
            tx_statuses: std::iter::repeat_with(|| Mutex::new(TransactionStatus::ReadyToExecute))
                .take(chunk_size)
                .collect(),
        }
    }

    /// Returns the done marker.
    pub fn done(&self) -> bool {
        todo!()
    }

    /// Checks if all transactions have been executed and validated.
    fn check_done(&self) {
        todo!()
    }

    pub fn next_task() -> Task {
        todo!()
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
        self.validation_index.fetch_min(target_index, Ordering::SeqCst);
        self.decrease_counter.fetch_add(1, Ordering::SeqCst);
    }

    fn decrease_execution_index(&self, target_index: TxIndex) {
        self.execution_index.fetch_min(target_index, Ordering::SeqCst);
        self.decrease_counter.fetch_add(1, Ordering::SeqCst);
    }

    /// Updates a transaction's status to `Executing` if it is ready to execute.
    fn try_incarnate(&self, tx_index: TxIndex) -> Option<TxIndex> {
        if tx_index < self.tx_statuses.len() {
            // TODO(barak, 01/04/2024): complete try_incarnate logic.
            return Some(tx_index);
        }
        self.n_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    fn next_version_to_validate(&self) -> Option<TxIndex> {
        let index_to_validate = self.validation_index.load(Ordering::Acquire);
        if index_to_validate >= self.tx_statuses.len() {
            self.check_done();
            return None;
        }
        self.n_active_tasks.fetch_add(1, Ordering::SeqCst);
        let index_to_validate = self.validation_index.fetch_add(1, Ordering::SeqCst);
        if index_to_validate < self.tx_statuses.len() {
            // TODO(barak, 01/04/2024): complete next_version_to_validate logic.
            return Some(index_to_validate);
        }
        self.n_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    fn next_version_to_execute(&self) -> Option<TxIndex> {
        let index_to_execute = self.execution_index.load(Ordering::Acquire);
        if index_to_execute >= self.tx_statuses.len() {
            self.check_done();
            return None;
        }
        self.n_active_tasks.fetch_add(1, Ordering::SeqCst);
        let index_to_execute = self.execution_index.fetch_add(1, Ordering::SeqCst);
        self.try_incarnate(index_to_execute)
    }
}

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
}
