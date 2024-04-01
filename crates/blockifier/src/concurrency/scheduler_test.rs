use pretty_assertions::assert_eq;
use rstest::rstest;

use crate::concurrency::scheduler::{Scheduler, TransactionStatus};

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
