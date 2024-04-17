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
    assert_eq!(scheduler.decrease_counter.into_inner(), 0);
    assert_eq!(scheduler.n_active_tasks.into_inner(), 0);
    assert_eq!(scheduler.chunk_size, chunk_size);
    assert_eq!(scheduler.tx_statuses.len(), chunk_size);
    for i in 0..chunk_size {
        assert_eq!(*scheduler.tx_statuses[i].lock().unwrap(), TransactionStatus::ReadyToExecute);
    }
    assert_eq!(scheduler.done_marker.into_inner(), false);
}

#[rstest]
#[case::done(DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE, 0, true)]
#[case::active_tasks(DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE, 1, false)]
#[case::execution_incomplete(DEFAULT_CHUNK_SIZE-1, DEFAULT_CHUNK_SIZE+1, 0, false)]
#[case::validation_incomplete(DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE-1, 0, false)]
fn test_check_done(
    #[case] execution_index: usize,
    #[case] validation_index: usize,
    #[case] n_active_tasks: usize,
    #[case] expected: bool,
) {
    let scheduler = default_scheduler!(
        chunk_size: DEFAULT_CHUNK_SIZE,
        execution_index: execution_index,
        validation_index: validation_index,
        n_active_tasks: n_active_tasks
    );
    scheduler.check_done();
    assert_eq!(scheduler.done_marker.load(Ordering::Acquire), expected);
}

#[rstest]
#[case::happy_flow(1, 0)]
#[should_panic(expected = "n_active_tasks underflow")]
#[case::underflow(0, 0)]
fn test_safe_decrement_n_active_tasks(
    #[case] n_active_tasks: usize,
    #[case] expected_n_active_tasks: usize,
) {
    let scheduler =
        default_scheduler!(chunk_size: DEFAULT_CHUNK_SIZE, n_active_tasks: n_active_tasks);
    scheduler.safe_decrement_n_active_tasks();
    assert_eq!(scheduler.n_active_tasks.load(Ordering::Acquire), expected_n_active_tasks);
}

#[rstest]
#[case::happy_flow(0, TransactionStatus::ReadyToExecute, false)]
#[should_panic(expected = "Status of transaction index 0 is poisoned. Data: ReadyToExecute.")]
#[case::poisoned(0, TransactionStatus::ReadyToExecute, true)]
fn test_lock_tx_status(
    #[case] tx_index: TxIndex,
    #[case] tx_status: TransactionStatus,
    #[case] should_poison_the_mutex: bool,
) {
    let arc_scheduler = Arc::new(Scheduler::new(DEFAULT_CHUNK_SIZE));
    if should_poison_the_mutex {
        let arc_scheduler_clone = arc_scheduler.clone();
        let handle = std::thread::spawn(move || {
            let _guard = arc_scheduler_clone.lock_tx_status(tx_index);
            panic!("Intentional panic to poison the mutex")
        });
        let result = handle.join();
        assert!(result.is_err());
    }
    let status = arc_scheduler.lock_tx_status(tx_index);
    assert_eq!(*status, tx_status);
}

#[rstest]
#[case::done(DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE, true, true, Task::Done, 0)]
#[case::no_task(DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE, false, true, Task::NoTask, 0)]
#[case::no_task_second_flow(DEFAULT_CHUNK_SIZE, 0, false, false, Task::NoTask, 0)]
#[case::execution_task(0, 0, false, true, Task::ExecutionTask(0), 1)]
#[case::validation_task(1, 0, false, true, Task::ValidationTask(0), 1)]
fn test_next_task(
    #[case] execution_index: usize,
    #[case] validation_index: usize,
    #[case] done_marker: bool,
    #[case] allow_status_change: bool,
    #[case] expected_next_task: Task,
    #[case] expected_n_active_tasks: usize,
) {
    let scheduler = default_scheduler!(
        chunk_size: DEFAULT_CHUNK_SIZE,
        execution_index: execution_index,
        validation_index: validation_index,
        done_marker: done_marker,
    );
    if allow_status_change
        && validation_index < execution_index
        && validation_index < DEFAULT_CHUNK_SIZE
    {
        let mut status = scheduler.lock_tx_status(validation_index);
        *status = TransactionStatus::Executed;
    }
    let next_task = scheduler.next_task();
    assert_eq!(next_task, expected_next_task);
    assert_eq!(scheduler.n_active_tasks.load(Ordering::Acquire), expected_n_active_tasks);
}

#[rstest]
#[case::target_index_lt_validation_index(1, 3, 1)]
#[case::target_index_eq_validation_index(3, 3, 0)]
#[case::target_index_eq_validation_index_eq_zero(0, 0, 0)]
#[case::target_index_gt_validation_index(1, 0, 0)]
fn test_decrease_validation_index(
    #[case] target_index: TxIndex,
    #[case] validation_index: usize,
    #[case] expected_decrease_counter: usize,
) {
    let scheduler =
        default_scheduler!(chunk_size: DEFAULT_CHUNK_SIZE, validation_index: validation_index);
    scheduler.decrease_validation_index(target_index);
    let expected_validation_index = min(target_index, validation_index);
    assert_eq!(scheduler.validation_index.load(Ordering::Acquire), expected_validation_index);
    assert_eq!(scheduler.decrease_counter.load(Ordering::Acquire), expected_decrease_counter);
}

#[rstest]
#[case::target_index_lt_execution_index(1, 3, 1)]
#[case::target_index_eq_execution_index(3, 3, 0)]
#[case::target_index_eq_execution_index_eq_zero(0, 0, 0)]
#[case::target_index_gt_execution_index(1, 0, 0)]
fn test_decrease_execution_index(
    #[case] target_index: TxIndex,
    #[case] execution_index: usize,
    #[case] expected_decrease_counter: usize,
) {
    let scheduler =
        default_scheduler!(chunk_size: DEFAULT_CHUNK_SIZE, execution_index: execution_index);
    scheduler.decrease_execution_index(target_index);
    let expected_execution_index = min(target_index, execution_index);
    assert_eq!(scheduler.execution_index.load(Ordering::Acquire), expected_execution_index);
    assert_eq!(scheduler.decrease_counter.load(Ordering::Acquire), expected_decrease_counter);
}

#[rstest]
#[case::from_ready_to_execute_to_executing(0, Some(TransactionStatus::ReadyToExecute), Some(0), 1)]
#[case::executing(1, Some(TransactionStatus::Executing), None, 0)]
#[case::executed(1, Some(TransactionStatus::Executed), None, 0)]
#[case::aborting(1, Some(TransactionStatus::Aborting), None, 0)]
#[case::index_out_of_bounds(DEFAULT_CHUNK_SIZE, None, None, 0)]
fn test_try_incarnate(
    #[case] tx_index: usize,
    #[case] tx_status: Option<TransactionStatus>,
    #[case] expected_output: Option<usize>,
    #[case] expected_n_active_tasks: usize,
) {
    let scheduler = default_scheduler!(chunk_size: DEFAULT_CHUNK_SIZE, n_active_tasks: 1);
    if let Some(tx_status) = tx_status {
        let mut status = scheduler.lock_tx_status(tx_index);
        *status = tx_status;
    }
    assert_eq!(scheduler.try_incarnate(tx_index), expected_output);
    assert_eq!(scheduler.n_active_tasks.load(Ordering::Acquire), expected_n_active_tasks);
}

#[rstest]
#[case::ready(1, Some(TransactionStatus::ReadyToExecute), None, 2, 0)]
#[case::executing(1, Some(TransactionStatus::Executing), None, 2, 0)]
#[case::executed(1, Some(TransactionStatus::Executed), Some(1), 2, 1)]
#[case::aborting(1, Some(TransactionStatus::Aborting), None, 2, 0)]
#[case::index_out_of_bounds(DEFAULT_CHUNK_SIZE, None, None, DEFAULT_CHUNK_SIZE, 0)]
fn test_next_version_to_validate(
    #[case] validation_index: usize,
    #[case] tx_status: Option<TransactionStatus>,
    #[case] expected_output: Option<usize>,
    #[case] expected_validation_index: usize,
    #[case] expected_n_active_tasks: usize,
) {
    let scheduler =
        default_scheduler!(chunk_size: DEFAULT_CHUNK_SIZE, validation_index: validation_index);
    if let Some(tx_status) = tx_status {
        let mut status = scheduler.lock_tx_status(validation_index);
        *status = tx_status;
    }
    assert_eq!(scheduler.next_version_to_validate(), expected_output);
    assert_eq!(scheduler.validation_index.load(Ordering::Acquire), expected_validation_index);
    assert_eq!(scheduler.n_active_tasks.load(Ordering::Acquire), expected_n_active_tasks);
}

#[rstest]
#[case::ready(1, Some(TransactionStatus::ReadyToExecute), Some(1), 2, 1)]
#[case::executing(1, Some(TransactionStatus::Executing), None, 2, 0)]
#[case::executed(1, Some(TransactionStatus::Executed), None, 2, 0)]
#[case::aborting(1, Some(TransactionStatus::Aborting), None, 2, 0)]
#[case::index_out_of_bounds(DEFAULT_CHUNK_SIZE, None, None, DEFAULT_CHUNK_SIZE, 0)]
fn test_next_version_to_execute(
    #[case] execution_index: usize,
    #[case] tx_status: Option<TransactionStatus>,
    #[case] expected_output: Option<usize>,
    #[case] expected_execution_index: usize,
    #[case] expected_n_active_tasks: usize,
) {
    let scheduler =
        default_scheduler!(chunk_size: DEFAULT_CHUNK_SIZE, execution_index: execution_index);
    if let Some(tx_status) = tx_status {
        let mut status = scheduler.lock_tx_status(execution_index);
        *status = tx_status;
    }
    assert_eq!(scheduler.next_version_to_execute(), expected_output);
    assert_eq!(scheduler.execution_index.load(Ordering::Acquire), expected_execution_index);
    assert_eq!(scheduler.n_active_tasks.load(Ordering::Acquire), expected_n_active_tasks);
}
