use std::cmp::min;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use pretty_assertions::assert_eq;
use rstest::rstest;

use crate::concurrency::scheduler::{Scheduler, Task, TransactionStatus};
use crate::concurrency::test_utils::DEFAULT_CHUNK_SIZE;
use crate::concurrency::TxIndex;
use crate::default_scheduler;

#[rstest]
fn test_new(#[values(0, 1, 32)] chunk_size: usize) {
    let scheduler = Scheduler::new(chunk_size);
    assert_eq!(scheduler.execution_index.into_inner(), 0);
    assert_eq!(scheduler.validation_index.into_inner(), chunk_size);
    assert_eq!(*scheduler.commit_index.lock().unwrap(), 0);
    assert_eq!(scheduler.chunk_size, chunk_size);
    assert_eq!(scheduler.tx_statuses.len(), chunk_size);
    for i in 0..chunk_size {
        assert_eq!(*scheduler.tx_statuses[i].lock().unwrap(), TransactionStatus::ReadyToExecute);
    }
    assert_eq!(scheduler.done_marker.into_inner(), false);
}

#[rstest]
fn test_lock_tx_status() {
    let scheduler = Scheduler::new(DEFAULT_CHUNK_SIZE);
    let status = scheduler.lock_tx_status(0);
    assert_eq!(*status, TransactionStatus::ReadyToExecute);
}

#[rstest]
#[should_panic(expected = "Cell of transaction index 0 is poisoned. Data: ReadyToExecute.")]
fn test_lock_tx_status_poisoned() {
    let scheduler = Arc::new(Scheduler::new(DEFAULT_CHUNK_SIZE));
    let scheduler_clone = scheduler.clone();
    let handle = std::thread::spawn(move || {
        let _guard = scheduler_clone.lock_tx_status(0);
        panic!("Intentional panic to poison the mutex")
    });
    handle.join().expect_err("Thread did not panic as expected");
    // The panic is expected here.
    let _guard = scheduler.lock_tx_status(0);
}

#[rstest]
#[case::done(DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE, TransactionStatus::Executed, Task::Done)]
#[case::no_task(
    DEFAULT_CHUNK_SIZE,
    DEFAULT_CHUNK_SIZE,
    TransactionStatus::Executed,
    Task::NoTaskAvailable
)]
#[case::no_task_as_validation_index_not_executed(
    DEFAULT_CHUNK_SIZE,
    0,
    TransactionStatus::ReadyToExecute,
    Task::AskForTask
)]
#[case::execution_task(0, 0, TransactionStatus::ReadyToExecute, Task::ExecutionTask(0))]
#[case::execution_task_as_validation_index_not_executed(
    1,
    0,
    TransactionStatus::ReadyToExecute,
    Task::ExecutionTask(1)
)]
#[case::validation_task(1, 0, TransactionStatus::Executed, Task::ValidationTask(0))]
fn test_next_task(
    #[case] execution_index: TxIndex,
    #[case] validation_index: TxIndex,
    #[case] validation_index_status: TransactionStatus,
    #[case] expected_next_task: Task,
) {
    let scheduler = default_scheduler!(
        chunk_size: DEFAULT_CHUNK_SIZE,
        execution_index: execution_index,
        validation_index: validation_index,
        done_marker: expected_next_task == Task::Done,
    );
    scheduler.set_tx_status(validation_index, validation_index_status);
    let next_task = scheduler.next_task();
    assert_eq!(next_task, expected_next_task);
}

#[rstest]
#[case::happy_flow(0, TransactionStatus::Executed, false)]
#[case::happy_flow_with_halt(0, TransactionStatus::Executed, true)]
#[case::last_transaction_to_commit(DEFAULT_CHUNK_SIZE - 1, TransactionStatus::Executed, false)]
#[case::last_transaction_to_commit_with_halt(DEFAULT_CHUNK_SIZE - 1, TransactionStatus::Executed, true)]
#[case::wrong_status_ready(0, TransactionStatus::ReadyToExecute, false)]
#[case::wrong_status_executing(0, TransactionStatus::Executing, false)]
#[case::wrong_status_aborting(0, TransactionStatus::Aborting, false)]
#[case::wrong_status_committed(0, TransactionStatus::Committed, false)]
fn test_commit_flow(
    #[case] commit_index: TxIndex,
    #[case] commit_index_tx_status: TransactionStatus,
    #[case] should_halt: bool,
) {
    let scheduler = default_scheduler!(chunk_size: DEFAULT_CHUNK_SIZE, commit_index: commit_index);
    scheduler.set_tx_status(commit_index, commit_index_tx_status);
    let mut transaction_committer = scheduler.try_enter_commit_phase().unwrap();
    // Lock is already acquired.
    assert!(scheduler.try_enter_commit_phase().is_none());
    if let Some(index) = transaction_committer.try_commit() {
        assert_eq!(index, commit_index);
    }
    if should_halt {
        transaction_committer.halt_scheduler();
    }
    drop(transaction_committer);
    if commit_index_tx_status == TransactionStatus::Executed {
        assert_eq!(*scheduler.lock_tx_status(commit_index), TransactionStatus::Committed);
        assert_eq!(
            *scheduler.commit_index.lock().unwrap(),
            if should_halt { commit_index } else { commit_index + 1 }
        );
        assert_eq!(
            scheduler.done_marker.load(Ordering::Acquire),
            commit_index + 1 == DEFAULT_CHUNK_SIZE || should_halt
        );
    } else {
        assert_eq!(*scheduler.lock_tx_status(commit_index), commit_index_tx_status);
        assert_eq!(*scheduler.commit_index.lock().unwrap(), commit_index);
    }
}

#[rstest]
#[case::reduces_validation_index(0, 3)]
#[case::does_not_reduce_validation_index(1, 0)]
fn test_finish_execution_during_commit(
    #[case] tx_index: TxIndex,
    #[case] validation_index: TxIndex,
) {
    let target_index = tx_index + 1;
    let scheduler =
        default_scheduler!(chunk_size: DEFAULT_CHUNK_SIZE, validation_index: validation_index);
    scheduler.finish_execution_during_commit(tx_index);
    let expected_validation_index = min(target_index, validation_index);
    assert_eq!(scheduler.validation_index.load(Ordering::Acquire), expected_validation_index);
}

#[rstest]
#[case::happy_flow(TransactionStatus::Executing)]
#[should_panic(expected = "Only executing transactions can gain status executed. Transaction 0 \
                           is not executing. Transaction status: ReadyToExecute.")]
#[case::wrong_status_ready(TransactionStatus::ReadyToExecute)]
#[should_panic(expected = "Only executing transactions can gain status executed. Transaction 0 \
                           is not executing. Transaction status: Executed.")]
#[case::wrong_status_executed(TransactionStatus::Executed)]
#[should_panic(expected = "Only executing transactions can gain status executed. Transaction 0 \
                           is not executing. Transaction status: Aborting.")]
#[case::wrong_status_aborting(TransactionStatus::Aborting)]
#[should_panic(expected = "Only executing transactions can gain status executed. Transaction 0 \
                           is not executing. Transaction status: Committed.")]
#[case::wrong_status_committed(TransactionStatus::Committed)]
fn test_set_executed_status(#[case] tx_status: TransactionStatus) {
    let tx_index = 0;
    let scheduler = Scheduler::new(DEFAULT_CHUNK_SIZE);
    scheduler.set_tx_status(tx_index, tx_status);
    // Panic is expected here in negative flows.
    scheduler.set_executed_status(tx_index);
    assert_eq!(*scheduler.lock_tx_status(tx_index), TransactionStatus::Executed);
}

#[rstest]
#[case::reduces_validation_index(0, 10)]
#[case::does_not_reduce_validation_index(10, 0)]
fn test_finish_execution(#[case] tx_index: TxIndex, #[case] validation_index: TxIndex) {
    let scheduler =
        default_scheduler!(chunk_size: DEFAULT_CHUNK_SIZE, validation_index: validation_index);
    scheduler.set_tx_status(tx_index, TransactionStatus::Executing);
    scheduler.finish_execution(tx_index);
    assert_eq!(*scheduler.lock_tx_status(tx_index), TransactionStatus::Executed);
    assert_eq!(scheduler.validation_index.load(Ordering::Acquire), min(tx_index, validation_index));
}

#[rstest]
#[case::happy_flow(TransactionStatus::Aborting)]
#[should_panic(expected = "Only aborting transactions can be re-executed. Transaction 0 is not \
                           aborting. Transaction status: ReadyToExecute.")]
#[case::wrong_status_ready(TransactionStatus::ReadyToExecute)]
#[should_panic(expected = "Only aborting transactions can be re-executed. Transaction 0 is not \
                           aborting. Transaction status: Executed.")]
#[case::wrong_status_executed(TransactionStatus::Executed)]
#[should_panic(expected = "Only aborting transactions can be re-executed. Transaction 0 is not \
                           aborting. Transaction status: Executing.")]
#[case::wrong_status_executing(TransactionStatus::Executing)]
#[should_panic(expected = "Only aborting transactions can be re-executed. Transaction 0 is not \
                           aborting. Transaction status: Committed.")]
#[case::wrong_status_committed(TransactionStatus::Committed)]
fn test_set_ready_status(#[case] tx_status: TransactionStatus) {
    let tx_index = 0;
    let scheduler = Scheduler::new(DEFAULT_CHUNK_SIZE);
    scheduler.set_tx_status(tx_index, tx_status);
    // Panic is expected here in negative flows.
    scheduler.set_ready_status(tx_index);
    assert_eq!(*scheduler.lock_tx_status(tx_index), TransactionStatus::ReadyToExecute);
}

#[rstest]
#[case::abort_validation(TransactionStatus::Executed)]
#[case::wrong_status_ready(TransactionStatus::ReadyToExecute)]
#[case::wrong_status_executing(TransactionStatus::Executing)]
#[case::wrong_status_aborted(TransactionStatus::Aborting)]
#[case::wrong_status_committed(TransactionStatus::Committed)]
fn test_try_validation_abort(#[case] tx_status: TransactionStatus) {
    let tx_index = 0;
    let scheduler = Scheduler::new(DEFAULT_CHUNK_SIZE);
    scheduler.set_tx_status(tx_index, tx_status);
    let result = scheduler.try_validation_abort(tx_index);
    assert_eq!(result, tx_status == TransactionStatus::Executed);
    if result {
        assert_eq!(*scheduler.lock_tx_status(tx_index), TransactionStatus::Aborting);
    }
}

#[rstest]
#[case::returns_execution_task(0, 10)]
#[case::does_not_return_execution_task(10, 0)]
fn test_finish_abort(#[case] tx_index: TxIndex, #[case] execution_index: TxIndex) {
    let scheduler =
        default_scheduler!(chunk_size: DEFAULT_CHUNK_SIZE, execution_index: execution_index,);
    scheduler.set_tx_status(tx_index, TransactionStatus::Aborting);
    let result = scheduler.finish_abort(tx_index);
    let new_status = scheduler.lock_tx_status(tx_index);
    if execution_index > tx_index {
        assert_eq!(result, Task::ExecutionTask(tx_index));
        assert_eq!(*new_status, TransactionStatus::Executing);
    } else {
        assert_eq!(result, Task::AskForTask);
        assert_eq!(*new_status, TransactionStatus::ReadyToExecute);
    }
}

#[rstest]
#[case::target_index_lt_validation_index(1, 3)]
#[case::target_index_eq_validation_index(3, 3)]
#[case::target_index_eq_validation_index_eq_zero(0, 0)]
#[case::target_index_gt_validation_index(1, 0)]
fn test_decrease_validation_index(
    #[case] target_index: TxIndex,
    #[case] validation_index: TxIndex,
) {
    let scheduler =
        default_scheduler!(chunk_size: DEFAULT_CHUNK_SIZE, validation_index: validation_index);
    scheduler.decrease_validation_index(target_index);
    let expected_validation_index = min(target_index, validation_index);
    assert_eq!(scheduler.validation_index.load(Ordering::Acquire), expected_validation_index);
}

#[rstest]
#[case::ready_to_execute(0, TransactionStatus::ReadyToExecute, true)]
#[case::executing(0, TransactionStatus::Executing, false)]
#[case::executed(0, TransactionStatus::Executed, false)]
#[case::aborting(0, TransactionStatus::Aborting, false)]
#[case::committed(0, TransactionStatus::Committed, false)]
#[case::index_out_of_bounds(DEFAULT_CHUNK_SIZE, TransactionStatus::ReadyToExecute, false)]
fn test_try_incarnate(
    #[case] tx_index: TxIndex,
    #[case] tx_status: TransactionStatus,
    #[case] expected_output: bool,
) {
    let scheduler = Scheduler::new(DEFAULT_CHUNK_SIZE);
    scheduler.set_tx_status(tx_index, tx_status);
    assert_eq!(scheduler.try_incarnate(tx_index), expected_output);
    if expected_output {
        assert_eq!(*scheduler.lock_tx_status(tx_index), TransactionStatus::Executing);
    } else if tx_index < DEFAULT_CHUNK_SIZE {
        assert_eq!(*scheduler.lock_tx_status(tx_index), tx_status);
    }
}

#[rstest]
#[case::ready_to_execute(1, TransactionStatus::ReadyToExecute, None)]
#[case::executing(1, TransactionStatus::Executing, None)]
#[case::executed(1, TransactionStatus::Executed, Some(1))]
#[case::aborting(1, TransactionStatus::Aborting, None)]
#[case::committed(1, TransactionStatus::Committed, None)]
#[case::index_out_of_bounds(DEFAULT_CHUNK_SIZE, TransactionStatus::ReadyToExecute, None)]
fn test_next_version_to_validate(
    #[case] validation_index: TxIndex,
    #[case] tx_status: TransactionStatus,
    #[case] expected_output: Option<TxIndex>,
) {
    let scheduler =
        default_scheduler!(chunk_size: DEFAULT_CHUNK_SIZE, validation_index: validation_index);
    scheduler.set_tx_status(validation_index, tx_status);
    assert_eq!(scheduler.next_version_to_validate(), expected_output);
    let expected_validation_index =
        if validation_index < DEFAULT_CHUNK_SIZE { validation_index + 1 } else { validation_index };
    assert_eq!(scheduler.validation_index.load(Ordering::Acquire), expected_validation_index);
}

#[rstest]
#[case::ready_to_execute(1, TransactionStatus::ReadyToExecute, Some(1))]
#[case::executing(1, TransactionStatus::Executing, None)]
#[case::executed(1, TransactionStatus::Executed, None)]
#[case::aborting(1, TransactionStatus::Aborting, None)]
#[case::committed(1, TransactionStatus::Committed, None)]
#[case::index_out_of_bounds(DEFAULT_CHUNK_SIZE, TransactionStatus::ReadyToExecute, None)]
fn test_next_version_to_execute(
    #[case] execution_index: TxIndex,
    #[case] tx_status: TransactionStatus,
    #[case] expected_output: Option<TxIndex>,
) {
    let scheduler =
        default_scheduler!(chunk_size: DEFAULT_CHUNK_SIZE, execution_index: execution_index);
    scheduler.set_tx_status(execution_index, tx_status);
    assert_eq!(scheduler.next_version_to_execute(), expected_output);
    let expected_execution_index =
        if execution_index < DEFAULT_CHUNK_SIZE { execution_index + 1 } else { execution_index };
    assert_eq!(scheduler.execution_index.load(Ordering::Acquire), expected_execution_index);
}
