use std::cmp::min;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use crate::concurrency::TxIndex;

#[cfg(test)]
#[path = "scheduler_test.rs"]
pub mod test;

#[derive(Debug, Default)]
pub struct Scheduler {
    execution_index: AtomicUsize,
    validation_index: AtomicUsize,
    // The index of the next transaction to commit. `commit_index` is protected by `commit_lock`.
    // There will be no concurrent access to `commit_index`, but the rust compiler cannot infer
    // that this is the case, so we use a Mutex to allow mutable and concurrent access.
    // TODO(Avi, 15/05/2024): Consider defining an ExplicitSyncWrapper for this.
    commit_index: Mutex<usize>,
    // Used to lock the commit index when committing transactions. This is necessary to make sure
    // the process of committing transactions is sequential.
    commit_lock: AtomicBool,
    chunk_size: usize,
    // TODO(Avi, 15/05/2024): Consider using RwLock instead of Mutex.
    tx_statuses: Box<[Mutex<TransactionStatus>]>,
    // Set to true when all transactions have been committed, or when calling the halt procedure,
    // providing a cheap way for all threads to exit their main loops.
    done_marker: AtomicBool,
    // Updated by the `halt` procedure. Used to signal to the first thread that halts that it
    // should perform the halt logic on the executor end.
    has_halted: AtomicBool,
}

impl Scheduler {
    pub fn new(chunk_size: usize) -> Scheduler {
        Scheduler {
            execution_index: AtomicUsize::new(0),
            validation_index: AtomicUsize::new(chunk_size),
            commit_index: Mutex::new(0),
            commit_lock: AtomicBool::new(false),
            chunk_size,
            tx_statuses: std::iter::repeat_with(|| Mutex::new(TransactionStatus::ReadyToExecute))
                .take(chunk_size)
                .collect(),
            done_marker: AtomicBool::new(false),
            has_halted: AtomicBool::new(false),
        }
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

    /// Updates the Scheduler that an execution task has been finished and triggers the creation of
    /// new tasks accordingly: schedules validation for the current and higher transactions, if not
    /// already scheduled.
    pub fn finish_execution(&self, tx_index: TxIndex) {
        self.set_executed_status(tx_index);
        if self.validation_index.load(Ordering::Acquire) > tx_index {
            self.decrease_validation_index(tx_index);
        }
    }

    pub fn try_validation_abort(&self, tx_index: TxIndex) -> bool {
        let mut status = self.lock_tx_status(tx_index);
        if *status == TransactionStatus::Executed {
            *status = TransactionStatus::Aborting;
            return true;
        }
        false
    }

    /// Updates the Scheduler that a validation task has been finished and triggers the creation of
    /// new tasks in case of failure: schedules validation for higher transactions + re-executes the
    /// current transaction (if ready).
    pub fn finish_validation(&self, tx_index: TxIndex, aborted: bool) -> Task {
        if aborted {
            self.set_ready_status(tx_index);
            if self.execution_index.load(Ordering::Acquire) > tx_index
                && self.try_incarnate(tx_index)
            {
                return Task::ExecutionTask(tx_index);
            }
        }

        Task::NoTask
    }

    /// Tries to commit the next transaction in the chunk. Returns the index of the transaction to
    /// commit if successful, or None if the transaction is not yet executed.
    /// Assumes that the caller has already acquired the commit lock.
    pub fn try_commit(&self) -> Option<usize> {
        let mut commit_index = self.commit_index.lock().expect(
            "This lock should always succeed, since commit_lock must be successfully acquired \
             before calling this method",
        );
        let mut status = self.lock_tx_status(*commit_index);
        if *status == TransactionStatus::Executed {
            *status = TransactionStatus::Committed;
            *commit_index += 1;
            if *commit_index == self.chunk_size {
                self.done_marker.store(true, Ordering::Release);
            }
            return Some(*commit_index - 1);
        }
        None
    }

    /// This method is called after a transaction gets re-executed during a commit. It decreases the
    /// validation index to ensure that higher transactions are validated. There is no need to set
    /// the transaction status to Executed, as it is already set to Committed.
    pub fn finish_execution_during_commit(&self, tx_index: TxIndex) {
        // We skipped decreasing the validation index when the transaction was executed, so we do it
        // now.
        self.decrease_validation_index(tx_index + 1);
    }

    // TODO(Avi, 15/05/2024): Remove dead_code attribute after using the commit lock.
    #[allow(dead_code)]
    fn try_commit_lock(&self) -> bool {
        self.commit_lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    // TODO(Avi, 15/05/2024): Remove dead_code attribute after using the commit lock.
    #[allow(dead_code)]
    fn unlock_commit_lock(&self) {
        self.commit_lock.store(false, Ordering::Release);
    }

    fn lock_tx_status(&self, tx_index: TxIndex) -> MutexGuard<'_, TransactionStatus> {
        self.tx_statuses[tx_index].lock().unwrap_or_else(|error| {
            panic!(
                "Status of transaction index {} is poisoned. Data: {:?}.",
                tx_index,
                *error.get_ref()
            )
        })
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

    /// Halts the scheduler. Returns true if the scheduler has not been halted before, false
    /// otherwise.
    fn halt(&self) -> bool {
        self.done_marker.store(true, Ordering::Release);
        !self.has_halted.swap(true, Ordering::SeqCst)
    }

    #[cfg(test)]
    fn set_tx_status(&self, tx_index: TxIndex, status: TransactionStatus) {
        if tx_index < self.chunk_size {
            let mut tx_status = self.lock_tx_status(tx_index);
            *tx_status = status;
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Task {
    ExecutionTask(TxIndex),
    ValidationTask(TxIndex),
    NoTask,
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum TransactionStatus {
    ReadyToExecute,
    Executing,
    Executed,
    Aborting,
    Committed,
}
