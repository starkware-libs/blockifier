use std::cmp::min;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::concurrency::Version;

#[cfg(test)]
#[path = "scheduler_test.rs"]
pub mod test;

pub struct Scheduler {
    pub execution_idx: AtomicU32,
    pub validation_idx: AtomicU32,
    pub decrease_counter: AtomicU32,
    pub n_active_tasks: AtomicU32,
    pub done_marker: AtomicBool,
    pub n_transactions: u32,
}

impl Scheduler {
    pub fn new(n_transactions: u32) -> Scheduler {
        Scheduler {
            execution_idx: AtomicU32::new(0),
            validation_idx: AtomicU32::new(0),
            decrease_counter: AtomicU32::new(0),
            n_active_tasks: AtomicU32::new(0),
            done_marker: AtomicBool::new(false),
            n_transactions,
        }
    }

    pub fn done(&self) -> bool {
        self.done_marker.load(Ordering::Acquire)
    }

    pub fn check_done(&self) {
        let observed_decrease_counter = self.decrease_counter.load(Ordering::Acquire);
        let validation_idx = self.validation_idx.load(Ordering::Acquire);
        let execution_idx = self.execution_idx.load(Ordering::Acquire);
        let n_active_tasks = self.n_active_tasks.load(Ordering::Acquire);

        if min(validation_idx, execution_idx) >= self.n_transactions
            && n_active_tasks == 0
            && observed_decrease_counter == self.decrease_counter.load(Ordering::Acquire)
        {
            self.done_marker.store(true, Ordering::Release);
        }
    }

    /// Return the next task to run. Prioritize validations tasks.
    pub fn next_task(&self) -> Task {
        loop {
            if self.done() {
                return Task::Done;
            }

            let idx_to_validate = self.validation_idx.load(Ordering::Acquire);
            let idx_to_execute = self.execution_idx.load(Ordering::Acquire);

            if min(idx_to_validate, idx_to_execute) >= self.n_transactions {
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
    /// Update the Scheduler that an execution task has been finished and trigger the creation of
    /// new tasks accordingly: schedule validation for the current and higher transactions, if
    /// not already scheduled.
    pub fn finish_execution(&self) -> Task {
        todo!()
    }

    // TODO(barak, 01/04/2024): Ensure documentation matches logic.
    /// Update the Scheduler that a validation task has been finished and trigger the creation of
    /// new tasks accordingly: schedule validation for higher transactions + re-executes the
    /// current transaction (if ready).
    pub fn finish_validation(&self) -> Task {
        todo!()
    }

    pub fn decrease_validation_idx(&self, target_idx: u32) {
        self.validation_idx.fetch_min(target_idx, Ordering::SeqCst);
        self.decrease_counter.fetch_add(1, Ordering::SeqCst);
    }

    pub fn decrease_execution_idx(&self, target_idx: u32) {
        self.execution_idx.fetch_min(target_idx, Ordering::SeqCst);
        self.decrease_counter.fetch_add(1, Ordering::SeqCst);
    }

    pub fn try_incarnate(&self, tx_idx: u32) -> Option<u32> {
        if tx_idx < self.n_transactions {
            // TODO: implement tx_status
            // if tx_status == TxStatus::ReadyToExecute
            //     tx_status = TxStatus::Executing
            return Some(tx_idx);
        }
        self.n_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    pub fn next_version_to_validate(&self) -> Option<u32> {
        let idx_to_validate = self.validation_idx.load(Ordering::Acquire);
        if idx_to_validate >= self.n_transactions {
            self.check_done();
            return None;
        }
        self.n_active_tasks.fetch_add(1, Ordering::SeqCst);
        let idx_to_validate = self.validation_idx.fetch_add(1, Ordering::SeqCst);
        if idx_to_validate < self.n_transactions {
            // TODO: implement tx_status
            // if tx_status == TxStatus::Executed
            return Some(idx_to_validate);
        }
        self.n_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    pub fn next_version_to_execute(&self) -> Option<u32> {
        let idx_to_execute = self.execution_idx.load(Ordering::Acquire);
        if idx_to_execute >= self.n_transactions {
            self.check_done();
            return None;
        }
        self.n_active_tasks.fetch_add(1, Ordering::SeqCst);
        let idx_to_execute = self.execution_idx.fetch_add(1, Ordering::SeqCst);
        self.try_incarnate(idx_to_execute)
    }
}

pub enum Task {
    ExecutionTask(Version),
    ValidationTask(Version),
    NoTask,
    Done,
}