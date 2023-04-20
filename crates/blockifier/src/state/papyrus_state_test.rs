use indexmap::IndexMap;
use papyrus_storage::db::DbConfig;
use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use papyrus_storage::{open_storage, StorageReader, StorageWriter};
use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::{StateDiff, StorageKey};
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, patricia_key, stark_felt};
use tempfile::tempdir;

use crate::abi::abi_utils::selector_from_name;
use crate::execution::entry_point::{CallEntryPoint, CallExecution, Retdata};
use crate::retdata;
use crate::state::cached_state::CachedState;
use crate::state::papyrus_state::PapyrusStateReader;
use crate::state::state_api::StateReader;
use crate::test_utils::{
    get_deprecated_contract_class, trivial_external_entry_point, TEST_CLASS_HASH,
    TEST_CONTRACT_ADDRESS, TEST_CONTRACT_PATH,
};

pub fn get_test_config() -> DbConfig {
    let dir = tempdir().unwrap();
    DbConfig {
        path: dir.path().to_path_buf(),
        min_size: 1 << 20,    // 1MB
        max_size: 1 << 35,    // 32GB
        growth_step: 1 << 26, // 64MB
    }
}
pub fn get_test_storage() -> (StorageReader, StorageWriter) {
    let config = get_test_config();
    open_storage(config).unwrap()
}
#[test]
fn test_entry_point_with_papyrus_state() -> papyrus_storage::StorageResult<()> {
    let (storage_reader, mut storage_writer) = get_test_storage();

    // Initialize Storage: add test contract and class.
    let deployed_contracts = IndexMap::from([(
        ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS)),
        ClassHash(stark_felt!(TEST_CLASS_HASH)),
    )]);
    let state_diff = StateDiff { deployed_contracts, ..Default::default() };

    let test_contract = get_deprecated_contract_class(TEST_CONTRACT_PATH);
    let deprecated_declared_classes =
        IndexMap::from([(ClassHash(stark_felt!(TEST_CLASS_HASH)), test_contract)]);
    storage_writer
        .begin_rw_txn()?
        .append_state_diff(BlockNumber::default(), state_diff, deprecated_declared_classes)?
        .commit()?;

    let storage_tx = storage_reader.begin_ro_txn()?;
    let state_reader = storage_tx.get_state_reader()?;

    // BlockNumber is 1 due to the initialization step above.
    let block_number = BlockNumber(1);
    let papyrus_reader = PapyrusStateReader::new(state_reader, block_number, Default::default());
    let mut state = CachedState::new(papyrus_reader);

    // Call entrypoint that want to write to storage, which updates the cached state's write cache.
    let key = stark_felt!(1234);
    let value = stark_felt!(18);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        ..trivial_external_entry_point()
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
