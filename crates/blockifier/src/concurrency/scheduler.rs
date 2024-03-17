#[cfg(test)]
#[path = "scheduler_test.rs"]
pub mod test;

pub struct Scheduler;

impl Scheduler {
    pub fn done() -> bool {
        todo!()
    }

    pub fn next_task() -> Task {
        todo!()
    }

    // TODO(barak, 01/04/2024): Ensure documentation matches logic.
    /// Schedules the required tasks necessitated by the last task of the thread.
    /// Returns the next VALIDATION task that should be done by the thread if 'validation_idx` >
    /// 'tx_idx', otherwise, Task.kind is 'None'.
    pub fn finish_execution() -> Task {
        todo!()
    }

    // TODO(barak, 01/04/2024): Ensure documentation matches logic.
    /// Schedules the required tasks necessitated by the last task of the thread.
    /// Returns the next EXECUTION task that should be done by the thread if 'execution_idx` >
    /// 'tx_idx', otherwise, Task.kind is 'None'.
    pub fn finish_validation() -> Task {
        todo!()
    }
}

pub struct TaskVersion {
    pub tx_idx: usize,
}

pub enum TaskType {
    EXECUTION,
    VALIDATION,
}

pub struct Task {
    pub version: TaskVersion,
    pub ty: Option<TaskType>,
}
