use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use rstest::rstest;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::stark_felt;
use starknet_api::state::StorageKey;

use crate::concurrency::scheduler::{Scheduler, Task, TransactionStatus};
use crate::concurrency::test_utils::{
    contract_address, safe_versioned_state_for_testing, DEFAULT_CHUNK_SIZE,
};
use crate::concurrency::TxIndex;
use crate::state::cached_state::{ContractClassMapping, StateMaps};
use crate::state::state_api::StateReader;
use crate::storage_key;
use crate::test_utils::dict_state_reader::DictStateReader;

#[rstest]
fn scheduler_flow_test(
    contract_address: ContractAddress,
    // TODO(barak, 01/07/2024): Add a separate identical test and use the package loom.
    #[values(1, 2, 4, 32, 64)] num_threads: u8,
) {
    // Simulate DEFAULT_CHUNK_SIZE txs. Each reads (contract_address, storage_key) and writes its tx
    // index (w.r.t the chunk) to the same storage cell.
    let scheduler = Arc::new(Scheduler::new(DEFAULT_CHUNK_SIZE));
    let storage_key = storage_key!(27_u8);
    let versioned_state = safe_versioned_state_for_testing(DictStateReader::default());
    let mut handles = vec![];

    for _ in 0..num_threads {
        let scheduler = Arc::clone(&scheduler);
        let versioned_state = versioned_state.clone();
        let handle = std::thread::spawn(move || {
            let mut task = Task::NoTask;
            loop {
                // TODO(barak, 01/07/2024): Add committing logic.
                task = match task {
                    Task::ExecutionTask(tx_index) => {
                        let write_set = create_trivial_write_set_for_tx_index(
                            tx_index,
                            contract_address,
                            storage_key,
                        );
                        versioned_state
                            .pin_version(tx_index)
                            .apply_writes(&write_set, &ContractClassMapping::default());
                        scheduler.finish_execution(tx_index);
                        Task::NoTask
                    }
                    Task::ValidationTask(tx_index) => {
                        let versioned_state_proxy = versioned_state.pin_version(tx_index);
                        let current_cell_value = versioned_state_proxy
                            .get_storage_at(contract_address, storage_key)
                            .unwrap();
                        let read_set = create_trivial_read_set_from_value(
                            current_cell_value,
                            contract_address,
                            storage_key,
                        );
                        let read_set_valid = versioned_state_proxy.validate_reads(&read_set);
                        let aborted = !read_set_valid && scheduler.try_validation_abort(tx_index);
                        if aborted {
                            let write_set = create_trivial_write_set_for_tx_index(
                                tx_index,
                                contract_address,
                                storage_key,
                            );
                            versioned_state_proxy
                                .delete_writes(&write_set, &ContractClassMapping::default());
                        }
                        scheduler.finish_validation(tx_index, aborted)
                    }
                    Task::NoTask => scheduler.next_task(),
                    Task::Done => break,
                }
            }
        });
        handles.push(handle);
    }
    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(scheduler.execution_index.load(Ordering::Acquire), DEFAULT_CHUNK_SIZE);
    assert!(scheduler.validation_index.load(Ordering::Acquire) >= DEFAULT_CHUNK_SIZE);
    // TODO(barak, 01/07/2024): Add to `commit_index` assertion once committing logic is added.
    assert_eq!(scheduler.n_active_tasks.load(Ordering::Acquire), 0);
    assert!(scheduler.done_marker.load(Ordering::Acquire));
    for tx_index in 0..DEFAULT_CHUNK_SIZE {
        // TODO(barak, 01/07/2024): Change to `Committed` status once committing logic is added.
        assert_eq!(*scheduler.tx_statuses[tx_index].lock().unwrap(), TransactionStatus::Executed);
        let storage_writes = versioned_state.state().get_writes_of_index(tx_index).storage;
        assert_eq!(
            *storage_writes.get(&(contract_address, storage_key)).unwrap(),
            stark_felt!(format!("{:x}", tx_index).as_str())
        );
    }
}

fn create_trivial_write_set_for_tx_index(
    tx_index: TxIndex,
    contract_address: ContractAddress,
    storage_key: StorageKey,
) -> StateMaps {
    StateMaps {
        storage: HashMap::from([(
            (contract_address, storage_key),
            stark_felt!(format!("{:x}", tx_index).as_str()),
        )]),
        ..Default::default()
    }
}

fn create_trivial_read_set_from_value(
    value: StarkFelt,
    contract_address: ContractAddress,
    storage_key: StorageKey,
) -> StateMaps {
    StateMaps {
        storage: HashMap::from([((contract_address, storage_key), value)]),
        ..Default::default()
    }
}
