use blockifier::abi::abi_utils::selector_from_name;
use blockifier::execution::call_info::{CallExecution, Retdata};
use blockifier::execution::entry_point::CallEntryPoint;
use blockifier::retdata;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::StateReader;
use blockifier::test_utils::{
    get_deprecated_contract_class, trivial_external_entry_point, TEST_CLASS_HASH,
    TEST_CONTRACT_ADDRESS, TEST_CONTRACT_CAIRO0_PATH,
};
use indexmap::IndexMap;
use papyrus_storage::state::StateStorageWriter;
use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::{StateDiff, StorageKey};
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};

use crate::papyrus_state::PapyrusReader;

#[test]
fn test_entry_point_with_papyrus_state() -> papyrus_storage::StorageResult<()> {
    let ((storage_reader, mut storage_writer), _) = papyrus_storage::test_utils::get_test_storage();

    // Initialize Storage: add test contract and class.
    let deployed_contracts =
        IndexMap::from([(contract_address!(TEST_CONTRACT_ADDRESS), class_hash!(TEST_CLASS_HASH))]);
    let state_diff = StateDiff { deployed_contracts, ..Default::default() };

    let test_contract = get_deprecated_contract_class(TEST_CONTRACT_CAIRO0_PATH);
    let deprecated_declared_classes =
        IndexMap::from([(class_hash!(TEST_CLASS_HASH), test_contract)]);
    storage_writer
        .begin_rw_txn()?
        .append_state_diff(BlockNumber::default(), state_diff, deprecated_declared_classes)?
        .commit()?;

    // BlockNumber is 1 due to the initialization step above.
    let block_number = BlockNumber(1);
    let papyrus_reader = PapyrusReader::new(storage_reader, block_number);
    let mut state = CachedState::from(papyrus_reader);

    // Call entrypoint that want to write to storage, which updates the cached state's write cache.
    let key = stark_felt!(1234_u16);
    let value = stark_felt!(18_u8);
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
