use std::collections::HashMap;
use std::path::Path;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::{ContractClassV0, ContractClassV1};
use blockifier::execution::entry_point::{CallEntryPoint, CallExecution, Retdata};
use blockifier::retdata;
use blockifier::state::cached_state::{CachedState, MutRefState};
use blockifier::state::state_api::{State, StateReader};
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
    Calldata, ContractAddressSalt, DeployAccountTransaction, Fee, InvokeTransaction,
    InvokeTransactionV1, TransactionHash, TransactionSignature, TransactionVersion,
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
    let path = Path::new("/home/alon/Downloads/alpha4_validation_papyrus_db/012_mdbx.dat");
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
    dbg!(selector_from_name("increase_liquidity"));
    let block_number = BlockNumber(692118);
    let state_reader = PapyrusStateReader::new(state_reader, block_number);
    let papyrus_reader = PapyrusReader::new(&storage_tx, state_reader);
    let mut state = CachedState::new(papyrus_reader);
    let tx = Transaction::AccountTransaction(AccountTransaction::Invoke(InvokeTransaction::V1(
        InvokeTransactionV1 {
            transaction_hash: TransactionHash(stark_felt!(
                "0x00b47deaa50f803cd919caa85d18edd61ba0ce7dc2f26139ca970f3f925df485"
            )),
            max_fee: Fee(2000000000000),
            signature: TransactionSignature(vec![
                stark_felt!("0x0602c5e6e5d2c22640d61d9082532a70225f01cbefd2f5f058ca5dfa5d0f3664"),
                stark_felt!("0x03f4ea3edb77fd65828fa5a63206adc0cbd170ebf457614471d1d359ed978039"),
            ]),
            nonce: Nonce(stark_felt!(
                "0x00000000000000000000000000000000000000000000000000000000000000e2"
            )),
            sender_address: ContractAddress(patricia_key!(
                "0x06e7d34296427f01d6dda951a0d3be89593170cad8cb47c730516f298eb23773"
            )),
            calldata: calldata![
                stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000001"),
                stark_felt!("0x037e72c3c1083e7e04e6173cd55b14414d236e091b26aba1f363add739052f57"),
                stark_felt!("0x02d27a01d6ab1a3af3204bc20743c243a4cb52234dc93a907e7c8da4097acfa8"),
                stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                stark_felt!("0x000000000000000000000000000000000000000000000000000000000000000b"),
                stark_felt!("0x000000000000000000000000000000000000000000000000000000000000000b"),
                stark_felt!("0x00000000000000000000000000000000000000000000000000000000000001cf"),
                stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                stark_felt!("0x0000000000000000000000000000000000000000000000042c96f40959140000"),
                stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                stark_felt!("0x0000000000000000000000000000000000000000000000042c96f40959140000"),
                stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                stark_felt!("0x0000000000000000000000000000000000000000000000000000000063dcae42")
            ],
        },
    )));
    // let tx = Transaction::AccountTransaction(AccountTransaction::DeployAccount(
    //     DeployAccountTransaction {
    //         transaction_hash: TransactionHash(stark_felt!(
    //             "0x058144b8ec7f7e9229f3c167bb07bc9a875e800dc4bf31c14844b0063c0152bb"
    //         )),
    //         max_fee: Fee(100441477),
    //         signature: TransactionSignature(vec![
    //
    // stark_felt!("0x057ba570e9775aac8588700ccb38c74e1c90277250134df4cb1b0f29d266a217"),
    //
    // stark_felt!("0x0173c36b7fc14cfe7c8fd672ec1740e873f0d90b5a74cc814625b68aef78f8b0"),
    //         ]),
    //         version: TransactionVersion(stark_felt!(
    //             "0x0000000000000000000000000000000000000000000000000000000000000001"
    //         )),
    //         nonce: Nonce(stark_felt!(
    //             "0x0000000000000000000000000000000000000000000000000000000000000000"
    //         )),
    //         class_hash: ClassHash(stark_felt!(
    //             "0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918"
    //         )),
    //         contract_address: ContractAddress(patricia_key!(
    //             "0x02acc7a4a5b65d09d9be1d7dca07e9926f3d0421f977c671a3b275040a00a33d"
    //         )),
    //         contract_address_salt: ContractAddressSalt(stark_felt!(
    //             "0x07335c61ec25b499e32ae8d0f449ba0816f080f945fe283daaccf77e6eb0f6fd"
    //         )),
    //         constructor_calldata: calldata![
    //
    // stark_felt!("0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918"),
    //
    // stark_felt!("0x0079dc0da7c54b95f10aa182ad0a46400db63156920adb65eca2654c0945a463"),
    //
    // stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000002"),
    //
    // stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
    //             stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000000")
    //         ],
    //     },
    // ));
    let block_context = BlockContext {
        chain_id: ChainId("SN_GOERLI".to_string()),
        block_number: BlockNumber(692118),
        block_timestamp: BlockTimestamp(1675405193),
        sequencer_address: ContractAddress(patricia_key!(
            "0x01176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8"
        )),
        fee_token_address: ContractAddress(patricia_key!(
            "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
        )),
        vm_resource_fee_cost: HashMap::from([
            ("output_builtin".to_string(), 0.0),
            ("ecdsa_builtin".to_string(), 20.0),
            ("n_steps".to_string(), 0.0),
            ("bitwise_builtin".to_string(), 0.0),
            ("poseidon_builtin".to_string(), 0.0),
            ("pedersen_builtin".to_string(), 0.0),
            ("range_check_builtin".to_string(), 0.0),
            ("ec_op_builtin".to_string(), 10.0),
        ]),
        gas_price: 5751,
        invoke_tx_max_n_steps: 1000000,
        validate_max_n_steps: 1000000,
        max_recursion_depth: 50,
        is_0_10: false,
    };
    let class_hash = ClassHash(stark_felt!(
        "0x01789b3103c5d1389e16c08dbee705b49dd9443c5895bbc2844744399724ce40"
    ));
    pub const PATH: &str = "./feature_contracts/compiled/account_compiled.json";
    let contract_class = ContractClassV0::from_file(PATH).into();
    state.set_contract_class(&class_hash, contract_class).unwrap();
    let class_hash = ClassHash(stark_felt!(
        "0x0612fd0ec84ea5fd201c54a6dfbda3d762b11ccf096b3a8bae34d9d24608c4f9"
    ));
    pub const SWAP_PATH: &str = "./feature_contracts/compiled/swap_pool_compiled.json";
    let contract_class = ContractClassV0::from_file(SWAP_PATH).into();
    state.set_contract_class(&class_hash, contract_class).unwrap();
    let res = tx
        .execute_raw(
            &mut CachedState::new(MutRefState::new(&mut state)),
            &block_context,
            Fee(162408240),
        )
        .unwrap();
    assert_eq!(1, 0);
    let calldata = calldata![
        stark_felt!("0x0000000000000000000000000000000000000000000000000000000000000002"),
        stark_felt!("0x02e39818908f0da118fde6b88b52e4dbdf13d2e171e488507f40deb6811bde3f")
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
