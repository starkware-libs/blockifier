use std::collections::HashMap;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::execution::call_info::{CallExecution, Retdata};
use blockifier::execution::entry_point::CallEntryPoint;
use blockifier::retdata;
use blockifier::state::cached_state::CachedState;
use blockifier::state::global_cache::{GlobalContractCache, GLOBAL_CONTRACT_CACHE_SIZE_FOR_TEST};
use blockifier::state::state_api::StateReader;
use blockifier::test_utils::contracts::FeatureContract;
use blockifier::test_utils::{trivial_external_entry_point_new, CairoVersion};
use indexmap::IndexMap;
use papyrus_storage::class::ClassStorageWriter;
use papyrus_storage::state::StateStorageWriter;
use starknet_api::block::BlockNumber;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::state::{StateDiff, StorageKey};
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, felt};
use starknet_types_core::felt::Felt;

use crate::py_block_executor::PyBlockExecutor;
use crate::py_state_diff::PyBlockInfo;
use crate::py_utils::PyFelt;
use crate::state_readers::papyrus_state::PapyrusReader;

const LARGE_COMPILED_CONTRACT_JSON: &str = include_str!("large_compiled_contract.json");

#[test]
fn test_entry_point_with_papyrus_state() -> papyrus_storage::StorageResult<()> {
    let ((storage_reader, mut storage_writer), _) = papyrus_storage::test_utils::get_test_storage();

    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let test_class_hash = test_contract.get_class_hash();
    let test_class = test_contract.get_deprecated_contract_class();
    // Initialize Storage: add test contract and class.
    let deployed_contracts =
        IndexMap::from([(test_contract.get_instance_address(0), test_class_hash)]);
    let state_diff = StateDiff {
        deployed_contracts,
        deprecated_declared_classes: IndexMap::from([(test_class_hash, test_class.clone())]),
        ..Default::default()
    };

    let block_number = BlockNumber::default();
    storage_writer
        .begin_rw_txn()?
        .append_state_diff(block_number, state_diff.into())?
        .append_classes(block_number, Default::default(), &[(test_class_hash, &test_class)])?
        .commit()?;

    // BlockNumber is 1 due to the initialization step above.
    let block_number = BlockNumber(1);
    let papyrus_reader = PapyrusReader::new(
        storage_reader,
        block_number,
        GlobalContractCache::new(GLOBAL_CONTRACT_CACHE_SIZE_FOR_TEST),
    );
    let mut state = CachedState::from(papyrus_reader);

    // Call entrypoint that want to write to storage, which updates the cached state's write cache.
    let key = felt!(1234_u16);
    let value = felt!(18_u8);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        ..trivial_external_entry_point_new(test_contract)
    };
    let storage_address = entry_point_call.storage_address;
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![value])
    );

    // Verify that the state has changed.
    let storage_key = StorageKey::try_from(key).unwrap();
    let value_from_state = state.get_storage_at(storage_address, storage_key).unwrap();
    assert_eq!(value_from_state, value);

    Ok(())
}

#[test]
/// Edge case: adding a large contract to the global contract cache.
fn global_contract_cache_update_large_contract() {
    let mut raw_contract_class: serde_json::Value =
        serde_json::from_str(LARGE_COMPILED_CONTRACT_JSON).unwrap();

    // ABI is not required for execution.
    raw_contract_class
        .as_object_mut()
        .expect("A compiled contract must be a JSON object.")
        .remove("abi");

    let dep_casm: DeprecatedContractClass = serde_json::from_value(raw_contract_class)
        .expect("DeprecatedContractClass is not supported for this contract.");

    let temp_storage_path = tempfile::tempdir().unwrap().into_path();
    let mut block_executor = PyBlockExecutor::native_create_for_testing(
        Default::default(),
        Default::default(),
        temp_storage_path,
        4000,
    );
    block_executor
        .append_block(
            0,
            None,
            Default::default(),
            Default::default(),
            Default::default(),
            HashMap::from([(PyFelt::from(1_u8), serde_json::to_string(&dep_casm).unwrap())]),
        )
        .unwrap();

    block_executor
        .append_block(
            1,
            Some(PyFelt(Felt::ZERO)),
            PyBlockInfo { block_number: 1, ..PyBlockInfo::default() },
            Default::default(),
            Default::default(),
            HashMap::from([(PyFelt::from(1_u8), serde_json::to_string(&dep_casm).unwrap())]),
        )
        .unwrap();
}
