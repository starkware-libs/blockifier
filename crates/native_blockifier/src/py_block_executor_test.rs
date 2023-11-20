use std::collections::HashMap;

use blockifier::state::state_api::State;
use blockifier::test_utils::{get_test_contract_class, TEST_CLASS_HASH};
use cached::Cached;
use pretty_assertions::assert_eq;
use starknet_api::class_hash;
use starknet_api::core::ClassHash;
use starknet_api::hash::{StarkFelt, StarkHash};

use crate::py_block_executor::{PyBlockExecutor, PyGeneralConfig};
use crate::py_state_diff::PyBlockInfo;
use crate::py_utils::PyFelt;
use crate::test_utils::MockStorage;

#[test]
fn global_contract_cache_update() {
    // Initialize executor and set a contract class on the state.
    let temp_storage_path = tempfile::tempdir().unwrap().into_path();
    let mut block_executor =
        PyBlockExecutor::create_for_testing(PyGeneralConfig::default(), temp_storage_path);
    block_executor.setup_block_execution(PyBlockInfo::default()).unwrap();

    let class_hash = class_hash!(TEST_CLASS_HASH);
    let contract_class = get_test_contract_class();
    block_executor
        .tx_executor()
        .state
        .set_contract_class(&class_hash, contract_class.clone())
        .unwrap();

    // Finalizing a pending block doesn't update the global contract cache.
    let is_pending_block = true;
    block_executor.finalize(is_pending_block);
    assert_eq!(block_executor.global_contract_cache.lock().unwrap().cache_size(), 0);
    block_executor.teardown_block_execution();

    // Finalizing a non-pending block does update the global cache.
    block_executor.setup_block_execution(PyBlockInfo::default()).unwrap();
    block_executor.tx_executor().state.set_contract_class(&class_hash, contract_class).unwrap();
    let is_pending_block = false;
    block_executor.finalize(is_pending_block);
    assert_eq!(block_executor.global_contract_cache.lock().unwrap().cache_size(), 1);
    block_executor.teardown_block_execution();
}

#[test]
fn get_block_id_with_large_hash_value() {
    let mut max_class_hash = [0xF; 32];
    max_class_hash[0] = 9;
    let max_class_hash = Vec::from(max_class_hash);

    let expected_max_class_hash_as_py_felt = PyFelt(
        StarkFelt::new([
            0x9, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf,
            0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf,
        ])
        .unwrap(),
    );

    let storage =
        MockStorage { block_number_to_class_hash: HashMap::from([(1138, max_class_hash)]) };
    let block_executor = PyBlockExecutor::create_for_testing_with_storage(storage);

    assert_eq!(
        block_executor.get_block_id_at_target(1138).unwrap().unwrap(),
        expected_max_class_hash_as_py_felt
    );
}
