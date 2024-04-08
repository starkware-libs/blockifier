use std::collections::HashMap;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::execution::call_info::CallExecution;
use blockifier::execution::entry_point::CallEntryPoint;
use blockifier::state::state_api::State;
use blockifier::test_utils::cached_state::deprecated_create_test_state;
use blockifier::test_utils::{
    get_test_contract_class, trivial_external_entry_point, TEST_CLASS_HASH,
};
use cached::Cached;
use pretty_assertions::assert_eq;
use rayon::prelude::*;
use starknet_api::core::ClassHash;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, class_hash, stark_felt};

use crate::py_block_executor::{PyBlockExecutor, PyGeneralConfig};
use crate::py_state_diff::PyBlockInfo;
use crate::py_utils::PyFelt;
use crate::test_utils::MockStorage;

#[test]
fn test_native_entry_point_with_arg() {
    let mut v = vec![];
    for i in 0..5000 {
        v.push(i);
    }
    let start = std::time::Instant::now();
    v.par_iter()
        .map(|i| {
            let mut state = deprecated_create_test_state();
            let calldata = calldata![stark_felt!(500_u128)];
            let entry_point_call = CallEntryPoint {
                calldata,
                entry_point_selector: selector_from_name("recurse"),
                ..trivial_external_entry_point()
            };
            assert_eq!(
                entry_point_call.execute_directly(&mut state).unwrap().execution,
                CallExecution::default()
            );
            i
        })
        .collect::<Vec<&i32>>();
    // for _ in 0..1000 {
    //     let mut state = deprecated_create_test_state();
    //     let calldata = calldata![stark_felt!(500_u128)];
    //     let entry_point_call = CallEntryPoint {
    //         calldata,
    //         entry_point_selector: selector_from_name("recurse"),
    //         ..trivial_external_entry_point()
    //     };
    //     assert_eq!(
    //         entry_point_call.execute_directly(&mut state).unwrap().execution,
    //         CallExecution::default()
    //     );
    // }
    println!("Elapsed: {:?}", start.elapsed());
}

#[test]
fn global_contract_cache_update() {
    // Initialize executor and set a contract class on the state.
    let temp_storage_path = tempfile::tempdir().unwrap().into_path();
    let mut block_executor =
        PyBlockExecutor::create_for_testing(PyGeneralConfig::default(), temp_storage_path);
    let sentinel_block_number_and_hash = None; // Information does not exist for block 0.
    block_executor
        .setup_block_execution(PyBlockInfo::default(), sentinel_block_number_and_hash)
        .unwrap();

    let class_hash = class_hash!(TEST_CLASS_HASH);
    let contract_class = get_test_contract_class();
    block_executor
        .tx_executor()
        .state
        .set_contract_class(class_hash, contract_class.clone())
        .unwrap();

    // Finalizing a pending block doesn't update the global contract cache.
    let is_pending_block = true;
    block_executor.finalize(is_pending_block);
    assert_eq!(block_executor.global_contract_cache.lock().cache_size(), 0);
    block_executor.teardown_block_execution();

    // Finalizing a non-pending block does update the global cache.
    block_executor
        .setup_block_execution(PyBlockInfo::default(), sentinel_block_number_and_hash)
        .unwrap();
    block_executor.tx_executor().state.set_contract_class(class_hash, contract_class).unwrap();
    let is_pending_block = false;
    block_executor.finalize(is_pending_block);
    assert_eq!(block_executor.global_contract_cache.lock().cache_size(), 1);
    block_executor.teardown_block_execution();
}

#[test]
fn get_block_id() {
    let max_class_hash = [
        0x9, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf,
        0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf,
    ];
    let max_class_hash_vec = Vec::from(max_class_hash);
    let expected_max_class_hash_as_py_felt = PyFelt(StarkFelt::new(max_class_hash).unwrap());

    let storage =
        MockStorage { block_number_to_class_hash: HashMap::from([(1138, max_class_hash_vec)]) };
    let block_executor = PyBlockExecutor::create_for_testing_with_storage(storage);

    assert_eq!(
        block_executor.get_block_id_at_target(1138).unwrap().unwrap(),
        expected_max_class_hash_as_py_felt
    );
}
