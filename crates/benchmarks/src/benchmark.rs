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
// use blockifier::state::state_api::State;
use blockifier::test_utils::{
    get_contract_class, ACCOUNT_CONTRACT_PATH, TEST_ACCOUNT_CONTRACT_CLASS_HASH,
};
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use clap::Parser;
// use indexmap::IndexMap;
use papyrus_storage::db::DbConfig;
// use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use papyrus_storage::state::StateStorageReader;
use papyrus_storage::{open_storage, StorageReader, StorageWriter};
use starknet_api::block::BlockNumber;
use starknet_api::core::{ChainId, ClassHash, ContractAddress, PatriciaKey};
// use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
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

pub fn get_test_config() -> DbConfig {
    let dir = "/home/gc/workspace/blockifier/db";
    DbConfig {
        path: PathBuf::from(dir),
        min_size: 1 << 20,    // 1MB
        max_size: 1 << 35,    // 32GB
        growth_step: 1 << 26, // 64MB
    }
}
pub fn get_test_storage() -> (StorageReader, StorageWriter) {
    let config = get_test_config();
    open_storage(config).unwrap()
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let contracts_path = PathBuf::from("/home/gc/workspace/starkware/tmp/classes.json");
    let contracts_contents = fs::read_to_string(contracts_path).unwrap();
    let mut contracts: ContractMap = serde_json::from_str(&contracts_contents).unwrap();

    let (storage_reader, mut _storage_writer) = get_test_storage();
    let test_account_class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));

    let mut class_cache =
        HashMap::from([(test_account_class_hash, get_contract_class(ACCOUNT_CONTRACT_PATH))]);

    let mut n_txs = 0;
    let mut blocks = vec![];
    let mut n_declares = 0;

    for i in 0..args.n_blocks {
        println!("Gen Block: {}", i);
        let block_path = PathBuf::from(format!("/home/gc/workspace/starkware/tmp/{i}.json"));
        let block_contents = fs::read_to_string(block_path).unwrap();
        let mut block: Block = serde_json::from_str(&block_contents).unwrap();
        block.block_number = BlockNumber(block.block_number.0);
        let block = starknet_api::block::Block::try_from(block).unwrap();
        blocks.push(block);
    }
    let start = Instant::now();
    for (_i, block) in blocks.into_iter().enumerate() {
        println!("Work Block: {}", block.header.block_number);

        // let mut declared_classes: IndexMap<ClassHash, DeprecatedContractClass> =
        // Default::default();
        let storage_tx = storage_reader.begin_ro_txn()?;
        let state_reader = storage_tx.get_state_reader()?;
        let papyrus_reader =
            PapyrusStateReader::new(state_reader, block.header.block_number, class_cache);
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
                    let deprecated_contract = contracts.map.remove(&declare.class_hash()).unwrap();
                    // declared_classes.insert(declare.class_hash(), deprecated_contract.clone());
                    deprecated_contract.try_into().ok()
                } else {
                    None
                };

            let tx = Transaction::from_api(tx, blockifier_contract);
            tx.execute(&mut state, &block_context)?;
        }
        // let mut state_diff = state.to_state_diff();
        // state_diff.deprecated_declared_classes = declared_classes;
        // storage_writer
        //     .begin_rw_txn()?
        //     .append_state_diff(block.header.block_number, state_diff, IndexMap::default())?
        //     .commit()?;

        class_cache = state.state.class_cache;
    }

    println!("n_txs: {n_txs}, elapsed:{}", start.elapsed().as_secs_f32());
    dbg!(&n_declares);
    Ok(())
}
