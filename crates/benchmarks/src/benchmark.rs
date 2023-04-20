use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

// use std::time::Instant;
use benchmarks::ContractMap;
use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass;
use blockifier::state::cached_state::CachedState;
use blockifier::state::papyrus_state::PapyrusStateReader;
use blockifier::state::state_api::State;
use blockifier::test_utils::{
    get_deprecated_contract_class, ACCOUNT_CONTRACT_PATH, TEST_ACCOUNT_CONTRACT_CLASS_HASH,
};
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use clap::Parser;
use indexmap::IndexMap;
use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use starknet_api::block::BlockNumber;
use starknet_api::core::{ChainId, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::state::StateDiff;
use starknet_client::Block;

/// Command line args parser.
/// Exits with 0/1 if the input is formatted correctly/incorrectly.
#[derive(Parser, Debug)]
#[clap(version, verbatim_doc_comment)]
struct Args {
    /// The crate to benchmark file.
    // path: PathBuf,
    n_blocks: usize,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let contracts_path = PathBuf::from("/home/gc/workspace/starkware/tmp/classes.json");
    let contracts_contents = fs::read_to_string(contracts_path).unwrap();
    let contracts: ContractMap = serde_json::from_str(&contracts_contents).unwrap();

    let test_account_class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    // let class_hash_to_class =
    //     HashMap::from([(test_account_class_hash, get_contract_class(ACCOUNT_CONTRACT_PATH))]);

    // let address_to_class_hash = HashMap::from([(
    //     ContractAddress(PatriciaKey::try_from(stark_felt!("0x1")).unwrap()),
    //     test_account_class_hash,
    // )]);

    let (storage_reader, mut storage_writer) = papyrus_storage::test_utils::get_test_storage();

    let deployed_contracts = IndexMap::from([(
        ContractAddress(PatriciaKey::try_from(stark_felt!("0x1")).unwrap()),
        test_account_class_hash,
    )]);
    let state_diff = StateDiff { deployed_contracts, ..Default::default() };

    let deprecated_declared_classes = IndexMap::from([(
        test_account_class_hash,
        get_deprecated_contract_class(ACCOUNT_CONTRACT_PATH),
    )]);

    storage_writer
        .begin_rw_txn()?
        .append_state_diff(BlockNumber::default(), state_diff, deprecated_declared_classes)?
        .commit()?;

    let mut n_txs = 0;

    let mut blocks = vec![];
    let mut n_declares = 0;

    for i in 0..args.n_blocks {
        println!("Gen Block: {}", i + 1);
        let block_path = PathBuf::from(format!("/home/gc/workspace/starkware/tmp/{i}.json"));
        let block_contents = fs::read_to_string(block_path).unwrap();
        let mut block: Block = serde_json::from_str(&block_contents).unwrap();
        block.block_number = BlockNumber(block.block_number.0 + 1);
        let block = starknet_api::block::Block::try_from(block).unwrap();
        blocks.push(block);
    }
    let start = Instant::now();
    let mut contract_cache: HashMap<ClassHash, DeprecatedContractClass> = HashMap::new();
    for (_i, block) in blocks.into_iter().enumerate() {
        println!("Work Block: {}", block.header.block_number);

        let mut declared_classes: IndexMap<ClassHash, DeprecatedContractClass> = Default::default();
        let storage_tx = storage_reader.begin_ro_txn()?;
        let state_reader = storage_tx.get_state_reader()?;
        let papyrus_reader = PapyrusStateReader::new(state_reader, block.header.block_number);
        let mut state = CachedState::new(papyrus_reader);

        let cairo_resource_fee_weights = HashMap::from([
            (String::from("n_steps"), 0.01),
            (String::from("pedersen_builtin"), 1_f64),
            (String::from("range_check_builtin"), 1_f64),
            (String::from("ecdsa_builtin"), 1_f64),
            (String::from("bitwise_builtin"), 1_f64),
            (String::from("poseidon_builtin"), 1_f64),
            (String::from("output_builtin"), 1_f64),
            (String::from("ec_op_builtin"), 1_f64),
        ]);

        let block_context = BlockContext {
            chain_id: ChainId("PRIVATE_SN_POTC_GOERLI".to_string()),
            block_number: block.header.block_number,
            block_timestamp: block.header.timestamp,
            sequencer_address: ContractAddress(
                PatriciaKey::try_from(stark_felt!(
                    "0x46a89ae102987331d369645031b49c27738ed096f2789c24449966da4c6de6b"
                ))
                .unwrap(),
            ),
            fee_token_address: ContractAddress(
                PatriciaKey::try_from(stark_felt!(
                    "0x79b6769e8898e6ab08d7c377f9e321a8dcd1a76bc8a2a244ed7f0960d56fc6"
                ))
                .unwrap(),
            ),
            cairo_resource_fee_weights,
            gas_price: 1,
            invoke_tx_max_n_steps: 1000000,
            validate_max_n_steps: 1000000,
        };

        n_txs += block.body.transactions.len();
        for tx in block.body.transactions {
            let blockifier_contract: Option<ContractClass> =
                if let starknet_api::transaction::Transaction::Declare(declare) = &tx {
                    n_declares += 1;
                    let deprecated_contract =
                        contract_cache.entry(declare.class_hash()).or_insert_with(|| {
                            contracts.map.get(&declare.class_hash()).unwrap().clone()
                        });
                    declared_classes.insert(declare.class_hash(), deprecated_contract.clone());
                    deprecated_contract.clone().try_into().ok()
                } else {
                    None
                };
            // contracts.map.get(&i).map(|contract| contract.clone().try_into().unwrap());

            let tx = Transaction::from_api(tx, blockifier_contract);
            tx.execute(&mut state, &block_context)?;
        }
        let mut state_diff = state.to_state_diff();
        state_diff.deprecated_declared_classes = declared_classes;
        storage_writer
            .begin_rw_txn()?
            .append_state_diff(block.header.block_number, state_diff, IndexMap::default())?
            .commit()?;
    }

    println!("n_txs: {n_txs}, elapsed:{}", start.elapsed().as_secs_f32());
    dbg!(&n_declares);

    // let args = Args::parse();
    // let txs_path = args.path.join("tx_id_to_tx.json");
    // let contracs_path = args.path.join("tx_id_to_contracts.json");

    // let txs_contents = fs::read_to_string(txs_path).unwrap();
    // let txs: TxIdToTxFile = serde_json::from_str(&txs_contents).unwrap();

    // let contracts_contents = fs::read_to_string(contracs_path).unwrap();
    // let contracts: TxIdToDeprecatedContractClass =
    //     serde_json::from_str(&contracts_contents).unwrap();

    // let block_context = BlockContext {
    //     chain_id: ChainId("PRIVATE_SN_POTC_GOERLI".to_string()),
    //     block_number: BlockNumber(0),
    //     block_timestamp: starknet_api::block::BlockTimestamp(0),
    //     sequencer_address: ContractAddress(
    //         PatriciaKey::try_from(stark_felt!(
    //             "0x46a89ae102987331d369645031b49c27738ed096f2789c24449966da4c6de6b"
    //         ))
    //         .unwrap(),
    //     ),
    //     fee_token_address: ContractAddress(
    //         PatriciaKey::try_from(stark_felt!(
    //             "0x79b6769e8898e6ab08d7c377f9e321a8dcd1a76bc8a2a244ed7f0960d56fc6"
    //         ))
    //         .unwrap(),
    //     ),
    //     cairo_resource_fee_weights: HashMap::from_iter([("n_steps".to_string(), 0.01)]),
    //     gas_price: 1,
    //     invoke_tx_max_n_steps: 1000000,
    //     validate_max_n_steps: 1000000,
    // };
    // // Declare all the needed contracts.
    // let test_account_class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    // let class_hash_to_class =
    //     HashMap::from([(test_account_class_hash, get_contract_class(ACCOUNT_CONTRACT_PATH))]);
    // // Deploy the erc20 contract.
    // let address_to_class_hash = HashMap::from([(
    //     ContractAddress(PatriciaKey::try_from(stark_felt!("0x1")).unwrap()),
    //     test_account_class_hash,
    // )]);

    // let mut state = CachedState::new(DictStateReader {
    //     address_to_class_hash,
    //     class_hash_to_class,
    //     ..Default::default()
    // });

    // let mut err_count = 0;

    // let before = Instant::now();

    // for i in 0..1100 {
    //     let blockifier_contract: Option<ContractClass> =
    //         contracts.map.get(&i).map(|contract| contract.clone().try_into().unwrap());

    //     let starknet_api_tx = StarknetApiTransaction::from(txs.map[&i].tx.clone());

    //     let tx = Transaction::from_api(starknet_api_tx, blockifier_contract);
    //     let res = tx.execute(&mut state, &block_context);
    //     if res.is_err() {
    //         println!("{}", res.unwrap_err());
    //         err_count += 1;
    //     }
    // }
    // println!("Number errors: {err_count}");
    // println!("Elapsed time: {:.2?}", before.elapsed());
    Ok(())
}
