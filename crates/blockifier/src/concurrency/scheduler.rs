use std::cmp::min;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};

use crate::concurrency::utils::lock_mutex_in_array;
use crate::concurrency::TxIndex;

#[cfg(test)]
#[path = "scheduler_test.rs"]
pub mod test;

#[cfg(test)]
#[path = "flow_test.rs"]
pub mod flow_test;

pub struct TransactionCommitter<'a> {
    scheduler: &'a Scheduler,
    commit_index_guard: MutexGuard<'a, usize>,
}

impl<'a> TransactionCommitter<'a> {
    pub fn new(scheduler: &'a Scheduler, commit_index_guard: MutexGuard<'a, usize>) -> Self {
        Self { scheduler, commit_index_guard }
    }

    /// Tries to commit the next uncommitted transaction in the chunk. Returns the index of the
    /// transaction to commit if successful, or None if the transaction is not yet executed.
    pub fn try_commit(&mut self) -> Option<usize> {
        if self.scheduler.done() {
            return None;
        };
        assert!(
            *self.commit_index_guard < self.scheduler.chunk_size,
            "The commit index must be less than the chunk size, since the scheduler is not done."
        );

        let mut status = self.scheduler.lock_tx_status(*self.commit_index_guard);
        if *status != TransactionStatus::Executed {
            return None;
        }
        *status = TransactionStatus::Committed;
        *self.commit_index_guard += 1;
        if *self.commit_index_guard == self.scheduler.chunk_size {
            self.scheduler.done_marker.store(true, Ordering::Release);
        }
        Some(*self.commit_index_guard - 1)
    }

    /// Halts the scheduler. Decrements the commit index to indicate that the final transaction to
    /// commit has been excluded from the block.
    pub fn halt_scheduler(&mut self) {
        assert!(*self.commit_index_guard > 0, "Commit index underflow.");
        *self.commit_index_guard -= 1;

        self.scheduler.halt();
    }
}

#[derive(Debug, Default)]
pub struct Scheduler {
    execution_index: AtomicUsize,
    validation_index: AtomicUsize,
    // The index of the next transaction to commit.
    commit_index: Mutex<usize>,
    chunk_size: usize,
    // TODO(Avi, 15/05/2024): Consider using RwLock instead of Mutex.
    tx_statuses: Box<[Mutex<TransactionStatus>]>,
    // Set to true when all transactions have been committed, or when calling the halt_scheduler
    // procedure, providing a cheap way for all threads to exit their main loops.
    done_marker: AtomicBool,
}

impl Scheduler {
    pub fn new(chunk_size: usize) -> Scheduler {
        Scheduler {
            execution_index: AtomicUsize::new(0),
            validation_index: AtomicUsize::new(chunk_size),
            commit_index: Mutex::new(0),
            chunk_size,
            tx_statuses: std::iter::repeat_with(|| Mutex::new(TransactionStatus::ReadyToExecute))
                .take(chunk_size)
                .collect(),
            done_marker: AtomicBool::new(false),
        }
    }

    pub fn next_task(&self) -> Task {
        if self.done() {
            return Task::Done;
        }

        let index_to_validate = self.validation_index.load(Ordering::Acquire);
        let index_to_execute = self.execution_index.load(Ordering::Acquire);

        if min(index_to_validate, index_to_execute) >= self.chunk_size {
            return Task::NoTaskAvailable;
        }

        if index_to_validate < index_to_execute {
            if let Some(tx_index) = self.next_version_to_validate() {
                return Task::ValidationTask(tx_index);
            }
        }

        if let Some(tx_index) = self.next_version_to_execute() {
            return Task::ExecutionTask(tx_index);
        }

        Task::AskForTask
    }

    /// Updates the Scheduler that an execution task has been finished and triggers the creation of
    /// new tasks accordingly: schedules validation for the current and higher transactions, if not
    /// already scheduled.
    pub fn finish_execution(&self, tx_index: TxIndex) {
        self.set_executed_status(tx_index);
        self.decrease_validation_index(tx_index);
    }

    pub fn try_validation_abort(&self, tx_index: TxIndex) -> bool {
        let mut status = self.lock_tx_status(tx_index);
        if *status == TransactionStatus::Executed {
            *status = TransactionStatus::Aborting;
            return true;
        }
        false
    }

    /// Updates the Scheduler that a validation task has aborted and triggers the creation of new
    /// tasks: schedules validation for higher transactions + re-executes the current transaction
    /// (if ready).
    pub fn finish_abort(&self, tx_index: TxIndex) -> Task {
        self.set_ready_status(tx_index);
        if self.execution_index.load(Ordering::Acquire) > tx_index && self.try_incarnate(tx_index) {
            Task::ExecutionTask(tx_index)
        } else {
            Task::AskForTask
        }
    }

    /// This method is called after a transaction gets re-executed during a commit. It decreases the
    /// validation index to ensure that higher transactions are validated. There is no need to set
    /// the transaction status to Executed, as it is already set to Committed.
    pub fn finish_execution_during_commit(&self, tx_index: TxIndex) {
        self.decrease_validation_index(tx_index + 1);
    }

    /// Tries to takes the lock on the commit index. Returns a `TransactionCommitter` if successful,
    /// or None if the lock is already taken.
    pub fn try_enter_commit_phase(&self) -> Option<TransactionCommitter<'_>> {
        match self.commit_index.try_lock() {
            Ok(guard) => Some(TransactionCommitter::new(self, guard)),
            Err(TryLockError::WouldBlock) => None,
            Err(TryLockError::Poisoned(error)) => {
                panic!("Commit index is poisoned. Data: {:?}.", *error.get_ref())
            }
        }
    }

    pub fn get_n_committed_txs(&self) -> usize {
        *self.commit_index.lock().unwrap()
    }

    pub fn halt(&self) {
        self.done_marker.store(true, Ordering::Release);
    }

    fn lock_tx_status(&self, tx_index: TxIndex) -> MutexGuard<'_, TransactionStatus> {
        lock_mutex_in_array(&self.tx_statuses, tx_index)
    }

    fn set_executed_status(&self, tx_index: TxIndex) {
        let mut status = self.lock_tx_status(tx_index);
        assert_eq!(
            *status,
            TransactionStatus::Executing,
            "Only executing transactions can gain status executed. Transaction {tx_index} is not \
             executing. Transaction status: {status:?}."
        );
        *status = TransactionStatus::Executed;
    }

    fn set_ready_status(&self, tx_index: TxIndex) {
        let mut status = self.lock_tx_status(tx_index);
        assert_eq!(
            *status,
            TransactionStatus::Aborting,
            "Only aborting transactions can be re-executed. Transaction {tx_index} is not \
             aborting. Transaction status: {status:?}."
        );
        *status = TransactionStatus::ReadyToExecute;
    }

    fn decrease_validation_index(&self, target_index: TxIndex) {
        self.validation_index.fetch_min(target_index, Ordering::SeqCst);
    }

    /// Updates a transaction's status to `Executing` if it is ready to execute.
    fn try_incarnate(&self, tx_index: TxIndex) -> bool {
        if tx_index < self.chunk_size {
            let mut status = self.lock_tx_status(tx_index);
            if *status == TransactionStatus::ReadyToExecute {
                *status = TransactionStatus::Executing;
                return true;
            }
        }
        false
    }

    fn next_version_to_validate(&self) -> Option<TxIndex> {
        let index_to_validate = self.validation_index.load(Ordering::Acquire);
        if index_to_validate >= self.chunk_size {
            return None;
        }
        let index_to_validate = self.validation_index.fetch_add(1, Ordering::SeqCst);
        if index_to_validate < self.chunk_size {
            let status = self.lock_tx_status(index_to_validate);
            if *status == TransactionStatus::Executed {
                return Some(index_to_validate);
            }
        }
        None
    }

    fn next_version_to_execute(&self) -> Option<TxIndex> {
        let index_to_execute = self.execution_index.load(Ordering::Acquire);
        if index_to_execute >= self.chunk_size {
            return None;
        }
        let index_to_execute = self.execution_index.fetch_add(1, Ordering::SeqCst);
        if self.try_incarnate(index_to_execute) {
            return Some(index_to_execute);
        }
        None
    }

    /// Returns the done marker.
    fn done(&self) -> bool {
        self.done_marker.load(Ordering::Acquire)
    }

    #[cfg(any(feature = "testing", test))]
    pub fn set_tx_status(&self, tx_index: TxIndex, status: TransactionStatus) {
        if tx_index < self.chunk_size {
            let mut tx_status = self.lock_tx_status(tx_index);
            *tx_status = status;
        }
    }

    #[cfg(any(feature = "testing", test))]
    pub fn get_tx_status(&self, tx_index: TxIndex) -> MutexGuard<'_, TransactionStatus> {
        self.lock_tx_status(tx_index)
    }
}

#[derive(Debug, PartialEq)]
pub enum Task {
    ExecutionTask(TxIndex),
    ValidationTask(TxIndex),
    AskForTask,
    NoTaskAvailable,
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TransactionStatus {
    ReadyToExecute,
    Executing,
    Executed,
    Aborting,
    Committed,
}
