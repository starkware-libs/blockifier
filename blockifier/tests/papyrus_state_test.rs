use blockifier::execution::entry_point::{CallEntryPoint, CallExecution, Retdata};
use blockifier::state::cached_state::CachedState;
use blockifier::state::papyrus_state::PapyrusStateReader;
use blockifier::state::state_api::State;
use blockifier::test_utils::{
    get_test_contract_class, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS,
    TEST_STORAGE_READ_WRITE_SELECTOR,
};
use indexmap::IndexMap;
use papyrus_storage::test_utils::get_test_storage;
use papyrus_storage::{StateStorageReader, StateStorageWriter, StorageResult};
use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::state::{EntryPointType, StateDiff};
use starknet_api::transaction::Calldata;
use starknet_api::{patky, shash};

fn trivial_external_entry_point() -> CallEntryPoint {
    CallEntryPoint {
        class_hash: ClassHash(shash!(TEST_CLASS_HASH)),
        entry_point_type: EntryPointType::External,
        entry_point_selector: EntryPointSelector(shash!(0)),
        calldata: Calldata(vec![].into()),
        storage_address: ContractAddress::try_from(shash!(TEST_CONTRACT_ADDRESS)).unwrap(),
        caller_address: ContractAddress::default(),
    }
}

#[test]
fn test_entry_point_with_papyrus_state() -> StorageResult<()> {
    let (storage_reader, mut storage_writer) = get_test_storage();

    // Initialize Storage: add test contract and class.
    let deployed_contracts = IndexMap::from([(
        ContractAddress(patky!(TEST_CONTRACT_ADDRESS)),
        ClassHash(shash!(TEST_CLASS_HASH)),
    )]);
    let state_diff = StateDiff { deployed_contracts, ..Default::default() };
    let declared_classes =
        vec![(ClassHash(shash!(TEST_CLASS_HASH)), get_test_contract_class().into())];
    storage_writer
        .begin_rw_txn()?
        .append_state_diff(BlockNumber::default(), state_diff, declared_classes)?
        .commit()?;

    let storage_tx = storage_reader.begin_ro_txn()?;
    let state_reader = storage_tx.get_state_reader()?;

    // BlockNumber is 1 due to the initialization step above.
    let block_number = BlockNumber(1);
    let papyrus_reader = PapyrusStateReader::new(state_reader, block_number);
    let mut state = CachedState::new(papyrus_reader);

    // Call entrypoint that want to write to storage, which updates CachedState's write cache.
    let key = shash!(1234);
    let value = shash!(18);
    let calldata = Calldata(vec![key, value].into());
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(TEST_STORAGE_READ_WRITE_SELECTOR)),
        ..trivial_external_entry_point()
    };
    let storage_address = entry_point_call.storage_address;
    assert_eq!(
        entry_point_call.execute(&mut state).unwrap().execution,
        CallExecution { retdata: Retdata(vec![value].into()) }
    );

    // Verify that the state has changed.
    let value_from_state = *state.get_storage_at(storage_address, key.try_into().unwrap()).unwrap();
    assert_eq!(value_from_state, value);
    Ok(())
}
