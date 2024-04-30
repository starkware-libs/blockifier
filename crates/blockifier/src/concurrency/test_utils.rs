use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rstest::fixture;
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::{contract_address, patricia_key, stark_felt};

use crate::concurrency::versioned_state_proxy::VersionedState;
use crate::state::cached_state::CachedState;
use crate::state::state_api::StateReader;
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

#[fixture]
pub fn initial_state_for_testing() -> DictStateReader {
    DictStateReader {
        address_to_class_hash: HashMap::from([(
            contract_address!("0x1"),
            ClassHash(stark_felt!(27_u8)),
        )]),
        ..DictStateReader::default()
    }
}

pub fn versioned_state_for_testing(
    initial_state: impl StateReader,
) -> Arc<Mutex<VersionedState<CachedState<impl StateReader>>>> {
    Arc::new(Mutex::new(VersionedState::new(CachedState::new(initial_state))))
}
