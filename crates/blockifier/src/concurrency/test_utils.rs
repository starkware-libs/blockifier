use crate::concurrency::versioned_state_proxy::{ThreadSafeVersionedState, VersionedState};
use crate::test_utils::dict_state_reader::DictStateReader;

#[macro_export]
macro_rules! default_scheduler {
    ($chunk_size:ident : $chunk:expr , $($field:ident $(: $value:expr)?),+ $(,)?) => {
        Scheduler {
            $chunk_size: $chunk,
            $($field $(: $value.into())?,)*
            tx_statuses: std::iter::repeat_with(|| std::sync::Mutex::new(
                    $crate::concurrency::scheduler::TransactionStatus::ReadyToExecute
                ))
                .take($chunk)
                .collect(),
            ..Default::default()
        }
    };
    ($chunk_size:ident $(, $field:ident $(: $value:expr)?),+ $(,)?) => {
        Scheduler {
            $chunk_size,
            $($field $(: $value.into())?,)*
            tx_statuses: std::iter::repeat_with(|| std::sync::Mutex::new(
                    $crate::concurrency::scheduler::TransactionStatus::ReadyToExecute
                ))
                .take($chunk_size)
                .collect(),
            ..Default::default()
        }
    };
}

// TODO(meshi, 01/06/2024): Consider making this a macro.
pub fn safe_versioned_state_for_testing(
    block_state: DictStateReader,
) -> ThreadSafeVersionedState<DictStateReader> {
    ThreadSafeVersionedState::new(VersionedState::new(block_state))
}
