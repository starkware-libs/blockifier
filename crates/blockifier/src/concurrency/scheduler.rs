use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(test)]
#[path = "scheduler_test.rs"]
pub mod test;

// TODO(Avi, 01/04/2024): Remove dead_code attribute.
#[allow(dead_code)]
#[derive(Default)]
pub struct Scheduler {
    execution_index: AtomicUsize,
    validation_index: AtomicUsize,
    /// Read twice upon checking the chunk completion. Used to detect if validation or execution
    /// index decreased from their observed values after ensuring that the number of active tasks
    /// is zero.
    decrease_counter: AtomicUsize,
    n_active_tasks: AtomicUsize,
    chunk_size: usize,
}

// TODO(Avi, 01/04/2024): Remove dead_code attribute.
#[allow(dead_code)]
impl Scheduler {
    pub fn new(chunk_size: usize) -> Scheduler {
        Scheduler { chunk_size, validation_index: chunk_size.into(), ..Default::default() }
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

    fn decrease_validation_index(&self, target_index: usize) {
        self.validation_index.fetch_min(target_index, Ordering::SeqCst);
        self.decrease_counter.fetch_add(1, Ordering::SeqCst);
    }

    fn decrease_execution_index(&self, target_index: usize) {
        self.execution_index.fetch_min(target_index, Ordering::SeqCst);
        self.decrease_counter.fetch_add(1, Ordering::SeqCst);
    }

    /// Updates a transaction's status to `Executing` if it is ready to execute.
    fn try_incarnate(&self, tx_index: usize) -> Option<usize> {
        if tx_index < self.chunk_size {
            // TODO(barak, 01/04/2024): complete try_incarnate logic.
            return Some(tx_index);
        }
        self.n_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    fn next_version_to_validate(&self) -> Option<usize> {
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

    fn next_version_to_execute(&self) -> Option<usize> {
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
    ExecutionTask(usize),
    ValidationTask(usize),
    NoTask,
    Done,
}
