use std::sync::atomic::Ordering;

use pretty_assertions::assert_eq;
use rstest::rstest;

use crate::concurrency::scheduler::{Scheduler, TransactionStatus};
use crate::concurrency::TxIndex;
use crate::default_scheduler;

const DEFAULT_CHUNK_SIZE: usize = 100;

#[rstest]
fn test_done() {
    // TODO(barak, 01/04/2024): Add test body.
    assert_eq!(0, 0)
}

#[rstest]
fn test_next_task() {
    // TODO(barak, 01/04/2024): Add test body.
    assert_eq!(0, 0)
}

#[rstest]
fn test_finish_execution() {
    // TODO(barak, 01/04/2024): Add test body.
    assert_eq!(0, 0)
}

#[rstest]
fn test_finish_validation() {
    // TODO(barak, 01/04/2024): Add test body.
    assert_eq!(0, 0)
}

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
}

#[rstest]
#[case::happy_flow(1, 3)]
#[should_panic(expected = "assertion failed: target_index < self.validation_index")]
#[case::target_index_eq_validation_index(3, 3)]
#[should_panic(expected = "assertion failed: target_index < self.validation_index")]
#[case::target_index_eq_validation_index_eq_zero(0, 0)]
#[should_panic(expected = "assertion failed: target_index < self.validation_index")]
#[case::target_index_gt_validation_index(1, 0)]
fn test_decrease_validation_index(#[case] target_index: TxIndex, #[case] validation_index: usize) {
    let scheduler =
        default_scheduler!(chunk_size: DEFAULT_CHUNK_SIZE, validation_index: validation_index);
    let decrease_counter_before = scheduler.decrease_counter.load(Ordering::Acquire);

    scheduler.decrease_validation_index(target_index);
    let decrease_counter_after = scheduler.decrease_counter.load(Ordering::Acquire);
    assert_eq!(scheduler.validation_index.load(Ordering::Acquire), target_index);
    assert_eq!(decrease_counter_before + 1, decrease_counter_after);
}
