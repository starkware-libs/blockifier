use std::cmp::min;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::concurrency::Version;

#[cfg(test)]
#[path = "scheduler_test.rs"]
pub mod test;

// TODO(Avi, 01/04/2024): Remove dead_code attribute.
#[allow(dead_code)]
#[derive(Default)]
pub struct Scheduler {
    execution_index: AtomicU32,
    validation_index: AtomicU32,
    /// Read twice upon checking the chunk completion. Used to detect if validation or execution
    /// index decreased from their observed values after ensuring that the number of active tasks
    /// is zero.
    decrease_counter: AtomicU32,
    n_active_tasks: AtomicU32,
    chunk_size: u32,
    /// Updated by the `check_done` procedure, providing a cheap way for all threads to exit their
    /// main loops.
    done_marker: AtomicBool,
}

// TODO(Avi, 01/04/2024): Remove dead_code attribute.
#[allow(dead_code)]
impl Scheduler {
    pub fn new(chunk_size: u32) -> Scheduler {
        Scheduler { chunk_size, validation_index: (chunk_size + 1).into(), ..Default::default() }
    }

    /// Returns the done marker.
    pub fn done(&self) -> bool {
        self.done_marker.load(Ordering::Acquire)
    }

    /// Checks if all transactions have been executed and validated.
    fn check_done(&self) {
        todo!()
    }

    pub fn next_task(&self) -> Task {
        loop {
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
                    return Task::ValidationTask(tx_index.into());
                }
            } else if let Some(tx_index) = self.next_version_to_execute() {
                return Task::ExecutionTask(tx_index.into());
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

    fn decrease_validation_index(&self, target_idx: u32) {
        self.validation_index.fetch_min(target_idx, Ordering::SeqCst);
        self.decrease_counter.fetch_add(1, Ordering::SeqCst);
    }

    fn decrease_execution_index(&self, target_idx: u32) {
        self.execution_index.fetch_min(target_idx, Ordering::SeqCst);
        self.decrease_counter.fetch_add(1, Ordering::SeqCst);
    }

    /// Updates a transaction's status to `Executing` if it is ready to execute.
    fn try_incarnate(&self, tx_idx: u32) -> Option<u32> {
        if tx_idx < self.chunk_size {
            // TODO(barak, 01/04/2024): complete try_incarnate logic.
            return Some(tx_idx);
        }
        self.n_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    fn next_version_to_validate(&self) -> Option<u32> {
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
        self.n_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    fn next_version_to_execute(&self) -> Option<u32> {
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

pub enum Task {
    ExecutionTask(Version),
    ValidationTask(Version),
    NoTask,
    Done,
}
