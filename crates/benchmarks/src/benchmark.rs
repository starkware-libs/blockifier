use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

// use std::time::Instant;
use benchmarks::ContractMap;
use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass;
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::{
    get_contract_class, DictStateReader, ACCOUNT_CONTRACT_PATH, TEST_ACCOUNT_CONTRACT_CLASS_HASH,
};
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use starknet_api::core::{ChainId, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_client::Block;

/// Command line args parser.
/// Exits with 0/1 if the input is formatted correctly/incorrectly.
// #[derive(Debug)]
// struct Args {
//     /// The crate to benchmark file.
//     path: PathBuf,
// }

fn main() -> anyhow::Result<()> {
    // let args = Args::parse();

    let contracts_path = PathBuf::from("/home/gc/workspace/starkware/tmp/classes.json");
    let contracts_contents = fs::read_to_string(contracts_path).unwrap();
    let contracts: ContractMap = serde_json::from_str(&contracts_contents).unwrap();

    let test_account_class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let class_hash_to_class =
        HashMap::from([(test_account_class_hash, get_contract_class(ACCOUNT_CONTRACT_PATH))]);
    let address_to_class_hash = HashMap::from([(
        ContractAddress(PatriciaKey::try_from(stark_felt!("0x1")).unwrap()),
        test_account_class_hash,
    )]);

    let mut state = CachedState::new(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        ..Default::default()
    });

    for i in 0..300 {
        println!("Block: {i}");
        let block_path = PathBuf::from(format!("/home/gc/workspace/starkware/tmp/{i}.json"));
        let block_contents = fs::read_to_string(block_path).unwrap();
        let block: Block = serde_json::from_str(&block_contents).unwrap();

        let block = starknet_api::block::Block::try_from(block).unwrap();

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
            cairo_resource_fee_weights: HashMap::from_iter([("n_steps".to_string(), 0.01)]),
            gas_price: 1,
            invoke_tx_max_n_steps: 1000000,
            validate_max_n_steps: 1000000,
        };

        for tx in block.body.transactions {
            let blockifier_contract: Option<ContractClass> =
                if let starknet_api::transaction::Transaction::Declare(declare) = &tx {
                    contracts
                        .map
                        .get(&declare.class_hash())
                        .map(|contract| contract.clone().try_into().unwrap())
                } else {
                    None
                };
            // contracts.map.get(&i).map(|contract| contract.clone().try_into().unwrap());

            let tx = Transaction::from_api(tx, blockifier_contract);
            let res = tx.execute(&mut state, &block_context);
            if res.is_err() {
                println!("{}", res.unwrap_err());
            }
        }
    }

    // let contracs_path = args.path.join("tx_id_to_contracts.json");

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
