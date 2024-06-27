use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use rstest::rstest;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::{contract_address, felt, patricia_key};

use crate::abi::sierra_types::{SierraType, SierraU128};
use crate::concurrency::scheduler::{Scheduler, Task, TransactionStatus};
use crate::concurrency::test_utils::{safe_versioned_state_for_testing, DEFAULT_CHUNK_SIZE};
use crate::concurrency::versioned_state::ThreadSafeVersionedState;
use crate::state::cached_state::{CachedState, ContractClassMapping, StateMaps};
use crate::state::state_api::UpdatableState;
use crate::storage_key;
use crate::test_utils::dict_state_reader::DictStateReader;

const CONTRACT_ADDRESS: &str = "0x18031991";
const STORAGE_KEY: u8 = 27;

#[rstest]
fn scheduler_flow_test(
    // TODO(barak, 01/07/2024): Add a separate identical test and use the package loom.
    #[values(1, 2, 4, 32, 64, 128)] num_threads: u8,
) {
    // Tests the Scheduler under a heavy load of validation aborts. To do that, we simulate multiple
    // transactions with multiple threads, where every transaction depends on its predecessor. Each
    // transaction sequentially advances a counter by reading the previous value and bumping it by
    // 1.
    let scheduler = Arc::new(Scheduler::new(DEFAULT_CHUNK_SIZE));
    let versioned_state =
        safe_versioned_state_for_testing(CachedState::from(DictStateReader::default()));
    let mut handles = vec![];

    for _ in 0..num_threads {
        let scheduler = Arc::clone(&scheduler);
        let versioned_state = versioned_state.clone();
        let handle = std::thread::spawn(move || {
            let mut task = Task::AskForTask;
            loop {
                if let Some(mut transaction_committer) = scheduler.try_enter_commit_phase() {
                    while let Some(tx_index) = transaction_committer.try_commit() {
                        let mut state_proxy = versioned_state.pin_version(tx_index);
                        let (reads, writes) =
                            get_reads_writes_for(Task::ValidationTask(tx_index), &versioned_state);
                        let reads_valid = state_proxy.validate_reads(&reads);
                        if !reads_valid {
                            state_proxy.delete_writes(&writes, &ContractClassMapping::default());
                            let (_, new_writes) = get_reads_writes_for(
                                Task::ExecutionTask(tx_index),
                                &versioned_state,
                            );
                            state_proxy.apply_writes(
                                &new_writes,
                                &ContractClassMapping::default(),
                                &HashMap::default(),
                            );
                            scheduler.finish_execution_during_commit(tx_index);
                        }
                    }
                }
                task = match task {
                    Task::ExecutionTask(tx_index) => {
                        let (_, writes) =
                            get_reads_writes_for(Task::ExecutionTask(tx_index), &versioned_state);
                        versioned_state.pin_version(tx_index).apply_writes(
                            &writes,
                            &ContractClassMapping::default(),
                            &HashMap::default(),
                        );
                        scheduler.finish_execution(tx_index);
                        Task::AskForTask
                    }
                    Task::ValidationTask(tx_index) => {
                        let state_proxy = versioned_state.pin_version(tx_index);
                        let (reads, writes) =
                            get_reads_writes_for(Task::ValidationTask(tx_index), &versioned_state);
                        let read_set_valid = state_proxy.validate_reads(&reads);
                        let aborted = !read_set_valid && scheduler.try_validation_abort(tx_index);
                        if aborted {
                            state_proxy.delete_writes(&writes, &ContractClassMapping::default());
                            scheduler.finish_abort(tx_index)
                        } else {
                            Task::AskForTask
                        }
                    }
                    Task::NoTaskAvailable => Task::AskForTask,
                    Task::AskForTask => scheduler.next_task(),
                    Task::Done => break,
                }
            }
        });
        handles.push(handle);
    }
    for handle in handles {
        handle.join().unwrap();
    }

    // The execution index can be strictly greater than chunk_size. This is a side effect of using
    // atomic variables instead of locks, which can encapsulate both the check (whether to increment
    // the variable or not) and the incrementation in a scope where no other threads can access the
    // variable.
    assert!(scheduler.execution_index.load(Ordering::Acquire) >= DEFAULT_CHUNK_SIZE);
    // There is no guarantee about the validation index because of the use of the commit index.
    assert!(*scheduler.commit_index.lock().unwrap() == DEFAULT_CHUNK_SIZE);
    assert!(scheduler.get_n_committed_txs() == DEFAULT_CHUNK_SIZE);
    assert!(scheduler.done_marker.load(Ordering::Acquire));
    let inner_versioned_state = versioned_state.into_inner_state();
    for tx_index in 0..DEFAULT_CHUNK_SIZE {
        assert_eq!(*scheduler.tx_statuses[tx_index].lock().unwrap(), TransactionStatus::Committed);
        let storage_writes = inner_versioned_state.get_writes_of_index(tx_index).storage;
        assert_eq!(
            *storage_writes
                .get(&(contract_address!(CONTRACT_ADDRESS), storage_key!(STORAGE_KEY)))
                .unwrap(),
            felt!(format!("{:x}", tx_index + 1).as_str())
        );
    }
}

fn get_reads_writes_for(
    task: Task,
    versioned_state: &ThreadSafeVersionedState<CachedState<DictStateReader>>,
) -> (StateMaps, StateMaps) {
    match task {
        Task::ExecutionTask(tx_index) => {
            let state_proxy = match tx_index {
                0 => {
                    return (
                        state_maps_with_single_storage_entry(0),
                        state_maps_with_single_storage_entry(1),
                    );
                }
                _ => versioned_state.pin_version(tx_index - 1),
            };
            let tx_written_value = SierraU128::from_storage(
                &state_proxy,
                &contract_address!(CONTRACT_ADDRESS),
                &storage_key!(STORAGE_KEY),
            )
            .unwrap()
            .as_value();
            (
                state_maps_with_single_storage_entry(tx_written_value),
                state_maps_with_single_storage_entry(tx_written_value + 1),
            )
        }
        Task::ValidationTask(tx_index) => {
            let state_proxy = versioned_state.pin_version(tx_index);
            let tx_written_value = SierraU128::from_storage(
                &state_proxy,
                &contract_address!(CONTRACT_ADDRESS),
                &storage_key!(STORAGE_KEY),
            )
            .unwrap()
            .as_value();
            (
                state_maps_with_single_storage_entry(tx_written_value - 1),
                state_maps_with_single_storage_entry(tx_written_value),
            )
        }
        _ => panic!("Only execution and validation tasks shold be used here."),
    }
}

fn state_maps_with_single_storage_entry(value: u128) -> StateMaps {
    StateMaps {
        storage: HashMap::from([(
            (contract_address!(CONTRACT_ADDRESS), storage_key!(STORAGE_KEY)),
            felt!(value),
        )]),
        ..Default::default()
    }
}
