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
use starknet_api::hash::StarkFelt;
use starknet_api::state::{StateDiff, StorageKey};
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, stark_felt};

use crate::state_readers::papyrus_state::PapyrusReader;

#[test]
fn test_entry_point_with_papyrus_state() -> papyrus_storage::StorageResult<()> {
    let ((storage_reader, mut storage_writer), _) = papyrus_storage::test_utils::get_test_storage();

    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let test_class_hash = test_contract.get_class_hash();
    // Initialize Storage: add test contract and class.
    let deployed_contracts =
        IndexMap::from([(test_contract.get_instance_address(0), test_class_hash)]);
    let state_diff = StateDiff { deployed_contracts, ..Default::default() };

    storage_writer
        .begin_rw_txn()?
        .append_state_diff(BlockNumber::default(), state_diff.into())?
        .append_classes(
            BlockNumber::default(),
            &[],
            &[(test_class_hash, &test_contract.get_deprecated_contract_class())],
        )?
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
    let key = stark_felt!(1234_u16);
    let value = stark_felt!(18_u8);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        ..trivial_external_entry_point_new(test_contract)
    };
    let storage_address = entry_point_call.storage_address;
    assert_eq!(
        entry_point_call.execute_directly(&mut state, None).unwrap().execution,
        CallExecution::from_retdata(retdata![value])
    );

    // Verify that the state has changed.
    let storage_key = StorageKey::try_from(key).unwrap();
    let value_from_state = state.get_storage_at(storage_address, storage_key).unwrap();
    assert_eq!(value_from_state, value);

    Ok(())
}
