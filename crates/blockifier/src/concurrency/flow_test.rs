use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use rstest::rstest;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::stark_felt;
use starknet_api::state::StorageKey;

use crate::abi::sierra_types::{stark_felt_to_u128, SierraType, SierraU128};
use crate::concurrency::scheduler::{Scheduler, Task, TransactionStatus};
use crate::concurrency::test_utils::{
    contract_address, safe_versioned_state_for_testing, DEFAULT_CHUNK_SIZE,
};
use crate::state::cached_state::{ContractClassMapping, StateMaps};
use crate::storage_key;
use crate::test_utils::dict_state_reader::DictStateReader;

#[rstest]
fn scheduler_flow_test(
    contract_address: ContractAddress,
    // TODO(barak, 01/07/2024): Add a separate identical test and use the package loom.
    #[values(1, 2, 4, 32, 64)] num_threads: u8,
) {
    // Tests the Scheduler under a heavy load of validation aborts. To do that, we simulate multiple
    // transactions with multiple threads, where every transaction depends on its predecessor. Each
    // transaction sequentially advances a counter by reading the previous value and bumping it by
    // 1.
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
                if let Some(mut transaction_committer) = scheduler.try_enter_commit_phase() {

                }
                task = match task {
                    Task::ExecutionTask(tx_index) => {
                        let state_proxy = versioned_state.pin_version(tx_index);
                        // Read previous counter value.
                        let counter =
                            SierraU128::from_storage(&state_proxy, &contract_address, &storage_key)
                                .unwrap();
                        // Advance counter and write to storage.
                        let writes = state_maps_with_single_storage_entry(
                            contract_address,
                            storage_key,
                            counter.as_value() + 1,
                        );
                        state_proxy.apply_writes(&writes, &ContractClassMapping::default());
                        scheduler.finish_execution(tx_index);
                        Task::NoTask
                    }
                    Task::ValidationTask(tx_index) => {
                        // Access the state's inners to get the tx's written (incremented) value by
                        // accessing. If no one has written to (contract_address, storage_key), it
                        // evaluates to 1 since this is the first write to the counter.
                        let tx_written_value = stark_felt_to_u128(
                            versioned_state
                                .state()
                                .get_writes_of_index(tx_index)
                                .storage
                                .get(&(contract_address, storage_key))
                                .unwrap_or(&StarkFelt::ONE),
                        )
                        .unwrap();
                        // If tx number tx_index wrote tx_written_value then it must have read
                        // tx_written_value - 1.
                        let read_set = state_maps_with_single_storage_entry(
                            contract_address,
                            storage_key,
                            tx_written_value - 1,
                        );
                        let state_proxy = versioned_state.pin_version(tx_index);
                        let read_set_valid = state_proxy.validate_reads(&read_set);
                        let aborted = !read_set_valid && scheduler.try_validation_abort(tx_index);
                        if aborted {
                            let write_set = state_maps_with_single_storage_entry(
                                contract_address,
                                storage_key,
                                tx_written_value,
                            );
                            state_proxy.delete_writes(&write_set, &ContractClassMapping::default());
                            scheduler.finish_abort(tx_index)
                        } else {
                            Task::NoTask
                        }
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

    // execution_index and validation_index can be strictly greater than chunk_size. This is a side
    // effect of using atomic variables instead of locks, which can encapsulate both the check
    // (whether to increment the variable or not) and the incrementation in a scope where no other
    // threads can access the variable.
    assert!(scheduler.execution_index.load(Ordering::Acquire) >= DEFAULT_CHUNK_SIZE);
    assert!(scheduler.validation_index.load(Ordering::Acquire) >= DEFAULT_CHUNK_SIZE);
    // TODO(barak, 01/07/2024): Add to `commit_index` assertion once committing logic is added.
    // assert_eq!(scheduler.n_active_tasks.load(Ordering::Acquire), 0);
    assert!(scheduler.done_marker.load(Ordering::Acquire));
    for tx_index in 0..DEFAULT_CHUNK_SIZE {
        // TODO(barak, 01/07/2024): Change to `Committed` status once committing logic is added.
        assert_eq!(*scheduler.tx_statuses[tx_index].lock().unwrap(), TransactionStatus::Executed);
        let storage_writes = versioned_state.state().get_writes_of_index(tx_index).storage;
        assert_eq!(
            *storage_writes.get(&(contract_address, storage_key)).unwrap(),
            stark_felt!(format!("{:x}", tx_index + 1).as_str())
        );
    }
}

fn state_maps_with_single_storage_entry(
    contract_address: ContractAddress,
    storage_key: StorageKey,
    value: u128,
) -> StateMaps {
    StateMaps {
        storage: HashMap::from([((contract_address, storage_key), stark_felt!(value))]),
        ..Default::default()
    }
}
