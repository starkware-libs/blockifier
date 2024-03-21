use std::sync::atomic::{AtomicU32, Ordering};

use crate::concurrency::Version;

#[cfg(test)]
#[path = "scheduler_test.rs"]
pub mod test;

pub const BLOCK_SIZE: u32 = 1000;

pub struct Scheduler {
    // The index of the next transaction to be executed.
    pub execution_idx: AtomicU32,
    // The index of the next transaction to be validated.
    pub validation_idx: AtomicU32,
    // The number of times the scheduler has decreased the execution/validation index.
    pub decrease_counter: AtomicU32,
    // The number of active tasks.
    pub n_active_tasks: AtomicU32,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub fn new() -> Scheduler {
        Scheduler {
            execution_idx: AtomicU32::new(0),
            validation_idx: AtomicU32::new(0),
            decrease_counter: AtomicU32::new(0),
            n_active_tasks: AtomicU32::new(0),
        }
    }

    pub fn done(&self) -> bool {
        todo!()
    }

    pub fn check_done(&self) {
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
        if tx_idx < BLOCK_SIZE {
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
        if idx_to_validate >= BLOCK_SIZE {
            self.check_done();
            return None;
        }
        self.n_active_tasks.fetch_add(1, Ordering::SeqCst);
        let idx_to_validate = self.validation_idx.fetch_add(1, Ordering::SeqCst);
        if idx_to_validate < BLOCK_SIZE {
            // TODO: implement tx_status
            // if tx_status == TxStatus::Executed
            return Some(idx_to_validate);
        }
        self.n_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    pub fn next_version_to_execute(&self) -> Option<u32> {
        let idx_to_execute = self.execution_idx.load(Ordering::Acquire);
        if idx_to_execute >= BLOCK_SIZE {
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
