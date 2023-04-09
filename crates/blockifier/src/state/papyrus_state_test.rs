use std::path::PathBuf;

use indexmap::IndexMap;
use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::{StateDiff, StorageKey};
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, patricia_key, stark_felt};

use crate::abi::abi_utils::selector_from_name;
use crate::execution::contract_class::DeprecatedContractClassWithoutAbi;
use crate::execution::entry_point::{CallEntryPoint, CallExecution, Retdata};
use crate::retdata;
use crate::state::cached_state::CachedState;
use crate::state::papyrus_state::PapyrusStateReader;
use crate::state::state_api::StateReader;
use crate::test_utils::{
    trivial_external_entry_point, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS, TEST_CONTRACT_PATH,
};

#[test]
fn test_entry_point_with_papyrus_state() {
    let (storage_reader, mut storage_writer) = papyrus_storage::test_utils::get_test_storage();

    // Initialize Storage: add test contract and class.
    let deployed_contracts = IndexMap::from([(
        ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS)),
        ClassHash(stark_felt!(TEST_CLASS_HASH)),
    )]);
    let state_diff = StateDiff { deployed_contracts, ..Default::default() };

    let test_contract_path = PathBuf::from(TEST_CONTRACT_PATH);
    let test_contract = DeprecatedContractClass::from(
        DeprecatedContractClassWithoutAbi::try_from(test_contract_path).unwrap(),
    );
    let deprecated_declared_classes =
        IndexMap::from([(ClassHash(stark_felt!(TEST_CLASS_HASH)), test_contract)]);
    storage_writer
        .begin_rw_txn()
        .unwrap()
        .append_state_diff(BlockNumber::default(), state_diff, deprecated_declared_classes)
        .unwrap()
        .commit()
        .unwrap();

    let storage_tx = storage_reader.begin_ro_txn().unwrap();
    let state_reader = storage_tx.get_state_reader().unwrap();

    // BlockNumber is 1 due to the initialization step above.
    let block_number = BlockNumber(1);
    let papyrus_reader = PapyrusStateReader::new(state_reader, block_number);
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
}
