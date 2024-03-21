use std::sync::atomic::{AtomicU32, Ordering};

use crate::concurrency::Version;

#[cfg(test)]
#[path = "scheduler_test.rs"]
pub mod test;

pub struct Scheduler {
    pub execution_idx: AtomicU32,
    pub validation_idx: AtomicU32,
    pub decrease_counter: AtomicU32,
    pub n_active_tasks: AtomicU32,
    pub n_transactions: u32,
}

impl Scheduler {
    pub fn new(n_transactions: u32) -> Scheduler {
        Scheduler {
            execution_idx: AtomicU32::new(0),
            validation_idx: AtomicU32::new(0),
            decrease_counter: AtomicU32::new(0),
            n_active_tasks: AtomicU32::new(0),
            n_transactions,
        }
    }

    pub fn done() -> bool {
        todo!()
    }

    pub fn check_done() -> () {
        todo!()
    }

    /// Return the next task to run. Prioratize validations tasks.
    pub fn next_task() -> Task {
        todo!()
    }

    // TODO(barak, 01/04/2024): Ensure documentation matches logic.
    /// Update the Scheduler that an execution task has been finished and trigger the creation of
    /// new tasks accordingly: schedule validation for the current and higher transactions, if
    /// not already scheduled.
    pub fn finish_execution() -> Task {
        todo!()
    }

    // TODO(barak, 01/04/2024): Ensure documentation matches logic.
    /// Update the Scheduler that a validation task has been finished and trigger the creation of
    /// new tasks accordingly: schedule validation for higher transactions + re-executes the
    /// current transaction (if ready).
    pub fn finish_validation() -> Task {
        todo!()
    }

    pub fn decrease_validation_idx(target_idx: u32) -> () {
        self.validation_idx.fetch_min(target_idx, Ordering::SeqCst);
        self.decrease_counter.fetch_add(1, Ordering::SeqCst);
    }

    pub fn decrease_execution_idx(target_idx: u32) -> () {
        self.execution_idx.fetch_min(target_idx, Ordering::SeqCst);
        self.decrease_counter.fetch_add(1, Ordering::SeqCst);
    }

    pub fn try_incarnate(tx_idx: u32) -> u32 {
        todo!()
    }

    pub fn next_version_to_validate() -> Option<u32> {
        let idx_to_validate = self.validation_idx.load(Ordering::Acquire);
        if idx_to_validate >= self.n_transactions {
            self.check_done();
            return None;
        }
        self.n_active_tasks.fetch_add(1, Ordering::SeqCst);
        idx_to_validate = self.validation_idx.fetch_add(1, Ordering::SeqCst);
        if idx_to_validate < self.n_transactions {
            // TODO: implement tx_status
            // if tx_status == TxStatus::Executed
            return idx_to_validate;
        }
        self.n_active_tasks.fetch_sub(1, Ordering::SeqCst);
        return None;
    }

    pub fn next_version_to_execute() -> Option<u32> {
        let idx_to_execute = self.execution_idx.load(Ordering::Acquire);
        if idx_to_execute >= self.n_transactions {
            self.check_done();
            return None;
        }
        self.n_active_tasks.fetch_add(1, Ordering::SeqCst);
        idx_to_execute = self.execution_idx.fetch_add(1, Ordering::SeqCst);
        return try_incarnate(idx_to_execute);
    }
}

pub enum Task {
    ExecutionTask(Version),
    ValidationTask(Version),
    NoTask,
    Done,
}
