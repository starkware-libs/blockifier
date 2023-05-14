use std::path::Path;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::execution::entry_point::{CallEntryPoint, CallExecution, Retdata};
use blockifier::retdata;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::{State, StateReader};
use blockifier::test_utils::{
    get_contract_class, get_deprecated_contract_class, trivial_external_entry_point,
    TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS, TEST_CONTRACT_PATH,
};
use indexmap::IndexMap;
use papyrus_storage::db::DbConfig;
use papyrus_storage::open_storage;
use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::{StateDiff, StorageKey};
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, patricia_key, stark_felt};

use crate::papyrus_state::PapyrusStateReader;

#[test]
fn test_entry_point_with_papyrus_state() -> papyrus_storage::StorageResult<()> {
    let (storage_reader, mut storage_writer) = papyrus_storage::test_utils::get_test_storage();

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

    Ok(())
}

#[test]
fn test_dur() -> papyrus_storage::StorageResult<()> {
    let path = Path::new("/home/alon/Downloads/alpha5_validation_papyrus_db/mdbx.dat");
    let config = DbConfig {
        path: path.to_path_buf(),
        min_size: 1 << 20,    // 1MB
        max_size: 1 << 35,    // 32GB
        growth_step: 1 << 26, // 64MB
    };
    let (reader, _) = open_storage(config).unwrap();
    let txn = reader.begin_ro_txn()?;
    let state_reader = txn.get_state_reader()?;
    // let block_number = reader.begin_ro_txn()?.get_state_marker()?;
    let block_number = BlockNumber(22026);
    let papyrus_reader = PapyrusStateReader::new(state_reader, block_number);
    let mut state = CachedState::new(papyrus_reader);
    let class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    pub const PATH: &str = "./feature_contracts/compiled/account_compiled.json";
    let contract_class = get_contract_class(PATH);
    state.set_contract_class(&class_hash, contract_class).unwrap();
    let calldata = calldata![
        stark_felt!("0x03e85bfbb8e2a42b7bead9e88e9a1b19dbccf661471061807292120462396ec9"),
        stark_felt!("0x00000000000000000000000000000000000000000000000006f05b59d3b20000"),
        stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        stark_felt!("0x00000000000000000000000000000000000000000000000006ccd46763f10000"),
        stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        stark_felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
        stark_felt!("0x000000000000000000000000000000000000000000000000002b842fe872168b"),
        stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        stark_felt!("0x000000000000000000000000000000000000000000000000002aa562265b5388"),
        stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000")
    ];
    let _entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("add_liquidity"),
        class_hash: Some(class_hash),
        storage_address: ContractAddress(patricia_key!(
            "0x018a439bcbb1b3535a6145c1dc9bc6366267d923f60a84bd0c7618f33c81d334"
        )),
        ..trivial_external_entry_point()
    };
    // assert_eq!(
    //     entry_point_call.execute_directly(&mut state).unwrap().execution,
    //     CallExecution::from_retdata(retdata![stark_felt!(23)])
    // );
    state
        .get_contract_class(&ClassHash(stark_felt!(
            "0x1e028264114492402a1fdde93a3bcb2ae7431687e0138827adf4a8eef7dcd70"
        )))
        .unwrap();
    // let keys = vec![
    //     "0x10064c6264bc3361adf2b26fd01272239473906cb7bbc183b1819e75188451",
    //     "0x1379ac0624b939ceb9dede92211d7db5ee174fe28be72245b0a1a2abd81c98f",
    //     "0x580876c1dffb2284696570e4a921706d20debb94971b2a2386d191b4dedda1f",
    //     "0x580876c1dffb2284696570e4a921706d20debb94971b2a2386d191b4dedda20",
    //     "0x580876c1dffb2284696570e4a921706d20debb94971b2a2386d191b4dedda21",
    //     "0x580876c1dffb2284696570e4a921706d20debb94971b2a2386d191b4dedda22",
    //     "0x580876c1dffb2284696570e4a921706d20debb94971b2a2386d191b4dedda23",
    //     "0x580876c1dffb2284696570e4a921706d20debb94971b2a2386d191b4dedda24",
    //     "0x580876c1dffb2284696570e4a921706d20debb94971b2a2386d191b4dedda25",
    // ];
    // for key in keys {
    //     dbg!(
    //         state
    //             .get_storage_at(
    //                 ContractAddress(patricia_key!(
    //                     "0x050426d7db96b196ddcfaab37d0f89b0e472b8d824518f2de95234ab1c6580aa"
    //                 )),
    //                 StorageKey(patricia_key!(key))
    //             )
    //             .unwrap()
    //     );
    // }
    // dbg!(
    //     state
    //         .get_class_hash_at(ContractAddress(patricia_key!(
    //             "0x046427f67eab8c7ce9d03da33b7d0a91e4fed5219d7b7cf7b9421459f8431ab3"
    //         )))
    //         .unwrap()
    // );

    Ok(())
}
