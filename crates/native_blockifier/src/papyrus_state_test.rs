use std::collections::HashMap;
use std::path::Path;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClassV0;
use blockifier::execution::entry_point::{CallEntryPoint, CallExecution, Retdata};
use blockifier::retdata;
use blockifier::state::cached_state::{CachedState, MutRefState};
use blockifier::state::state_api::{StateReader, State};
use blockifier::test_utils::{
    get_deprecated_contract_class, trivial_external_entry_point, TEST_CLASS_HASH,
    TEST_CONTRACT_ADDRESS, TEST_CONTRACT_PATH,
};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use indexmap::IndexMap;
use papyrus_storage::db::DbConfig;
use papyrus_storage::header::HeaderStorageReader;
use papyrus_storage::open_storage;
use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{
    ChainId, ClassHash, ContractAddress, EntryPointSelector, Nonce, PatriciaKey,
};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::{StateDiff, StorageKey};
use starknet_api::transaction::{
    Calldata, Fee, InvokeTransaction, InvokeTransactionV1, TransactionHash, TransactionSignature,
};
use starknet_api::{calldata, patricia_key, stark_felt};

use crate::papyrus_state::{PapyrusReader, PapyrusStateReader};

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
    let state_reader = PapyrusStateReader::new(state_reader, block_number);
    let papyrus_reader = PapyrusReader::new(&storage_tx, state_reader);
    let mut state = CachedState::new(papyrus_reader);

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

#[test]
fn test_dur() -> papyrus_storage::StorageResult<()> {
    let path = Path::new("/home/alon/Downloads/mainnet_validation_papyrus_db/012_mdbx.dat");
    let config = DbConfig {
        path: path.to_path_buf(),
        min_size: 1 << 20,    // 1MB
        max_size: 1 << 35,    // 32GB
        growth_step: 1 << 26, // 64MB
    };
    let (reader, _) = open_storage(config).unwrap();
    let storage_tx = reader.begin_ro_txn()?;
    let state_reader = storage_tx.get_state_reader()?;
    dbg!(reader.begin_ro_txn()?.get_header_marker()?);
    dbg!(reader.begin_ro_txn()?.get_state_marker()?);
    let block_number = BlockNumber(32004);
    let state_reader = PapyrusStateReader::new(state_reader, block_number);
    let papyrus_reader = PapyrusReader::new(&storage_tx, state_reader);
    let mut state = CachedState::new(papyrus_reader);
    // let tx = Transaction::AccountTransaction(AccountTransaction::Invoke(InvokeTransaction::V1(
    //     InvokeTransactionV1 {
    //         transaction_hash: TransactionHash(stark_felt!(
    //             "0x011bb18033d49a4c87be4804940b0d3ba1faebed466b4e1ece91266656c2ef3e"
    //         )),
    //         max_fee: Fee(2000000000000),
    //         signature: TransactionSignature(vec![
    //
    // stark_felt!("0x063ed9f9ca2fe9fd5b8483c0b86562713d3cf01fb17dd45442d1c21cb780e927"),
    //
    // stark_felt!("0x022c621dd03549aa13af0d4adac77b020ff268cbc9b6690acfb7fdc13c21fbf5"),
    //         ]),
    //         nonce: Nonce(stark_felt!(
    //             "0x0000000000000000000000000000000000000000000000000000000000000048"
    //         )),
    //         sender_address: ContractAddress(patricia_key!(
    //             "0x039618efb43fb60252d7804bc8cbce49863c4eab0c8f9b53dd8a53f15747889d"
    //         )),
    //         calldata: calldata![
    //
    // stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000001"),
    //
    // stark_felt!("0x060709b70f08092cee6d4d7f30203dfdbff649cb6bb6557663cdb3e86130a005"),
    //
    // stark_felt!("0x02c262d067f2b55b4cdc60aa399bdf75de5713f555ce969a6173cc6ea655c28b"),
    //
    // stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
    //
    // stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000001"),
    //
    // stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000001"),
    //             stark_felt!("0x006d949605cbfd465c271a535fb6a2e3eb952c1f8ffdc385930710860ceb72cc")
    //         ],
    //     },
    // )));
    // let block_context = BlockContext {
    //     chain_id: ChainId("SN_GOERLI2".to_string()),
    //     block_number: BlockNumber(78020),
    //     block_timestamp: BlockTimestamp(1675883517),
    //     sequencer_address: ContractAddress(patricia_key!(
    //         "0x046a89ae102987331d369645031b49c27738ed096f2789c24449966da4c6de6b"
    //     )),
    //     fee_token_address: ContractAddress(patricia_key!(
    //         "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
    //     )),
    //     vm_resource_fee_cost: HashMap::from([
    //         ("output_builtin".to_string(), 0.0),
    //         ("ecdsa_builtin".to_string(), 20.0),
    //         ("n_steps".to_string(), 0.0),
    //         ("bitwise_builtin".to_string(), 0.0),
    //         ("poseidon_builtin".to_string(), 0.0),
    //         ("pedersen_builtin".to_string(), 0.0),
    //         ("range_check_builtin".to_string(), 0.0),
    //         ("ec_op_builtin".to_string(), 10.0),
    //     ]),
    //     gas_price: 5639622,
    //     invoke_tx_max_n_steps: 1000000,
    //     validate_max_n_steps: 1000000,
    //     is_0_10: true,
    // };
    // tx.execute_raw(
    //     &mut CachedState::new(MutRefState::new(&mut state)),
    //     &block_context,
    //     Fee(133873347036),
    // )
    // .unwrap();
    // assert_eq!(1, 0);
    let class_hash = ClassHash(stark_felt!(
        "0x02c2b8f559e1221468140ad7b2352b1a5be32660d0bf1a3ae3a054a4ec5254e4"
    ));
    pub const PATH: &str = "./feature_contracts/compiled/account_compiled.json";
    let contract_class = ContractClassV0::from_file(PATH).into();
    state.set_contract_class(&class_hash, contract_class).unwrap();
    let calldata = calldata![
        stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000002"),
        stark_felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
        stark_felt!("0x0219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c"),
        stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000003"),
        stark_felt!("0x041fd22b238fa21cfcf5dd45a8548974d8263b3a531a60388411c5e230f97023"),
        stark_felt!("0x03b1bf5248b545038b97fc53525d5be840cf237a3faddfcaa7b9e4c8439fdaad"),
        stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000003"),
        stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000009"),
        stark_felt!("0x000000000000000000000000000000000000000000000000000000000000000c"),
        stark_felt!("0x041fd22b238fa21cfcf5dd45a8548974d8263b3a531a60388411c5e230f97023"),
        stark_felt!("0x00000000000000000000000000000000000000000000000000098adc931f310f"),
        stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        stark_felt!("0x0000000000000000000000000000000000000000000000004563918244f40000"),
        stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        stark_felt!("0x00000000000000000000000000000000000000000000000000098adc931f310f"),
        stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000002"),
        stark_felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
        stark_felt!("0x00da114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3"),
        stark_felt!("0x034ba5785a490663424df8be41386071f4bff5d98bbaf4ee95261dc863bcecbd"),
        stark_felt!("0x00000000000000000000000000000000000000000000000000000000642dd898")
    ];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(stark_felt!(
            "0x162da33a4585851fe8d3af3c2a9c60b557814e221e0d4f30ff0b2189d9c7775"
        )),
        class_hash: Some(class_hash),
        storage_address: ContractAddress(patricia_key!(
            "0x034ba5785a490663424df8be41386071f4bff5d98bbaf4ee95261dc863bcecbd"
        )),
        caller_address: ContractAddress(patricia_key!(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        )),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![stark_felt!(23_u8)])
    );
    // state
    //     .get_contract_class(&ClassHash(stark_felt!(
    //         "0x1e028264114492402a1fdde93a3bcb2ae7431687e0138827adf4a8eef7dcd70"
    //     )))
    //     .unwrap();
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
