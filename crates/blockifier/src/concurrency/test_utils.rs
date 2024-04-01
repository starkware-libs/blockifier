use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use starknet_api::core::{ClassHash, ContractAddress};

use crate::concurrency::versioned_state_proxy::VersionedState;
use crate::state::cached_state::CachedState;
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

// TODO: Allow the creation of VersionedState with different state readers.
pub fn versioned_state_for_testing(
    contract_address: ContractAddress,
    class_hash: ClassHash,
) -> Arc<Mutex<VersionedState<CachedState<DictStateReader>>>> {
    let mut address_to_class_hash = HashMap::new();
    address_to_class_hash.insert(contract_address, class_hash);

    let cached_state =
        CachedState::from(DictStateReader { address_to_class_hash, ..Default::default() });
    Arc::new(Mutex::new(VersionedState::new(cached_state)))
}
