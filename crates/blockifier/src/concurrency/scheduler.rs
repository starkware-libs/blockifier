use crate::concurrency::Version;

#[cfg(test)]
#[path = "scheduler_test.rs"]
pub mod test;

pub struct Scheduler;

impl Scheduler {
    pub fn done() -> bool {
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
}

pub enum Task {
    ExecutionTask(Version),
    ValidationTask(Version),
    NoTask,
    Done,
}
