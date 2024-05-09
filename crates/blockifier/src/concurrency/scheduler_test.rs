use std::cmp::min;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use pretty_assertions::assert_eq;
use rstest::rstest;

use crate::concurrency::scheduler::{Scheduler, Task, TransactionStatus};
use crate::concurrency::TxIndex;
use crate::default_scheduler;

const DEFAULT_CHUNK_SIZE: usize = 100;

#[rstest]
fn test_new(#[values(0, 1, 32)] chunk_size: usize) {
    let scheduler = Scheduler::new(chunk_size);
    assert_eq!(scheduler.execution_index.into_inner(), 0);
    assert_eq!(scheduler.validation_index.into_inner(), chunk_size);
    assert_eq!(scheduler.chunk_size, chunk_size);
    assert_eq!(scheduler.tx_statuses.len(), chunk_size);
    for i in 0..chunk_size {
        assert_eq!(*scheduler.tx_statuses[i].lock().unwrap(), TransactionStatus::ReadyToExecute);
    }
    assert_eq!(scheduler.done_marker.into_inner(), false);
    assert_eq!(scheduler.has_halted.into_inner(), false);
}

#[rstest]
fn test_lock_tx_status() {
    let scheduler = Scheduler::new(DEFAULT_CHUNK_SIZE);
    let status = scheduler.lock_tx_status(0);
    assert_eq!(*status, TransactionStatus::ReadyToExecute);
}

#[rstest]
#[should_panic(expected = "Status of transaction index 0 is poisoned. Data: ReadyToExecute.")]
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
#[case::no_task(DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE, TransactionStatus::Executed, Task::NoTask)]
#[case::no_task_as_validation_index_not_executed(
    DEFAULT_CHUNK_SIZE,
    0,
    TransactionStatus::ReadyToExecute,
    Task::NoTask
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
#[case::target_index_lt_execution_index(1, 3)]
#[case::target_index_eq_execution_index(3, 3)]
#[case::target_index_eq_execution_index_eq_zero(0, 0)]
#[case::target_index_gt_execution_index(1, 0)]
fn test_decrease_execution_index(#[case] target_index: TxIndex, #[case] execution_index: TxIndex) {
    let scheduler =
        default_scheduler!(chunk_size: DEFAULT_CHUNK_SIZE, execution_index: execution_index);
    scheduler.decrease_execution_index(target_index);
    let expected_execution_index = min(target_index, execution_index);
    assert_eq!(scheduler.execution_index.load(Ordering::Acquire), expected_execution_index);
}

#[rstest]
#[case::ready_to_execute(0, TransactionStatus::ReadyToExecute, true)]
#[case::executing(0, TransactionStatus::Executing, false)]
#[case::executed(0, TransactionStatus::Executed, false)]
#[case::aborting(0, TransactionStatus::Aborting, false)]
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
