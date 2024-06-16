use std::collections::HashMap;

use blockifier::blockifier::transaction_executor::BLOCK_STATE_ACCESS_ERR;
use blockifier::execution::contract_class::{ContractClass, ContractClassV1};
use blockifier::state::state_api::StateReader;
use cached::Cached;
use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use pretty_assertions::assert_eq;
use starknet_api::core::ClassHash;
use starknet_api::{class_hash, felt};
use starknet_types_core::felt::Felt;

use crate::py_block_executor::{PyBlockExecutor, PyGeneralConfig};
use crate::py_objects::PyConcurrencyConfig;
use crate::py_state_diff::{PyBlockInfo, PyStateDiff};
use crate::py_utils::PyFelt;
use crate::test_utils::MockStorage;

#[test]
fn global_contract_cache_update() {
    // Initialize executor and set a contract class on the state.
    let casm = CasmContractClass::default();
    let contract_class = ContractClass::V1(ContractClassV1::try_from(casm.clone()).unwrap());
    let class_hash = class_hash!("0x1");

    let temp_storage_path = tempfile::tempdir().unwrap().into_path();
    let mut block_executor = PyBlockExecutor::create_for_testing(
        PyConcurrencyConfig::default(),
        PyGeneralConfig::default(),
        temp_storage_path,
        4000,
    );
    block_executor
        .append_block(
            0,
            None,
            PyBlockInfo::default(),
            PyStateDiff::default(),
            HashMap::from([(
                class_hash.into(),
                (PyFelt::from(1_u8), serde_json::to_string(&casm).unwrap()),
            )]),
            HashMap::default(),
        )
        .unwrap();

    let sentinel_block_number_and_hash = None; // Information does not exist for block 0.
    block_executor
        .setup_block_execution(
            PyBlockInfo { block_number: 1, ..PyBlockInfo::default() },
            sentinel_block_number_and_hash,
        )
        .unwrap();

    assert_eq!(block_executor.global_contract_cache.lock().cache_size(), 0);

    let queried_contract_class = block_executor
        .tx_executor()
        .block_state
        .as_ref()
        .expect(BLOCK_STATE_ACCESS_ERR)
        .get_compiled_contract_class(class_hash)
        .unwrap();

    assert_eq!(queried_contract_class, contract_class);
    assert_eq!(block_executor.global_contract_cache.lock().cache_size(), 1);
}

#[test]
fn get_block_id() {
    let max_class_hash = [
        0x9, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf,
        0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf,
    ];
    let max_class_hash_vec = Vec::from(max_class_hash);
    let expected_max_class_hash_as_py_felt = PyFelt(Felt::from_bytes_be(&max_class_hash));

    let storage =
        MockStorage { block_number_to_class_hash: HashMap::from([(1138, max_class_hash_vec)]) };
    let block_executor = PyBlockExecutor::create_for_testing_with_storage(storage);

    assert_eq!(
        block_executor.get_block_id_at_target(1138).unwrap().unwrap(),
        expected_max_class_hash_as_py_felt
    );
}
