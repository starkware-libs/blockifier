//! Benchmark module for the blockifier crate. It provides functionalities to benchmark
//! various aspects related to transferring between accounts, including preparation
//! and execution of transfers.
//!
//! The main benchmark function is `transfers_benchmark`, which measures the performance
//! of transfers between randomly created accounts, which are iterated over round-robin.
//!
//! Run the benchmarks using `cargo bench --bench blockifier_bench`.

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::blockifier::transaction_executor::TransactionExecutor;
use blockifier::context::{BlockContext, ChainInfo};
use blockifier::invoke_tx_args;
use blockifier::test_utils::contracts::FeatureContract;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::initial_test_state::test_state;
use blockifier::test_utils::invoke::invoke_tx;
use blockifier::test_utils::{CairoVersion, NonceManager, BALANCE, MAX_FEE};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::transaction_execution::Transaction;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{Rng, SeedableRng};
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, Fee, TransactionVersion};
use starknet_api::{calldata, stark_felt};

const N_ACCOUNTS: u16 = 10000;
const CHUNK_SIZE: usize = 100;
const RANDOMIZATION_SEED: u64 = 0;
const CHARGE_FEE: bool = false;
const TRANSACTION_VERSION: TransactionVersion = TransactionVersion(StarkFelt::ONE);

pub fn transfers_benchmark(c: &mut Criterion) {
    let account_contract = FeatureContract::AccountWithLongValidate(CairoVersion::Cairo0);
    let block_context = BlockContext::create_for_account_testing();
    let chain_info = &block_context.chain_info().clone();
    let state = test_state(chain_info, BALANCE * 1000, &[(account_contract, N_ACCOUNTS)]);
    let executor =
        &mut TransactionExecutor::new(state, block_context, Default::default(), Default::default());
    let accounts = (0..N_ACCOUNTS)
        .map(|instance_id| account_contract.get_instance_address(instance_id))
        .collect::<Vec<_>>();
    let nonce_manager = &mut NonceManager::default();

    let mut sender_account = 0;
    let mut random_generator = rand::rngs::StdRng::seed_from_u64(RANDOMIZATION_SEED);
    // Create a benchmark group called "transfers", which iterates over the accounts round-robin
    // and performs transfers.
    c.bench_function("transfers", |benchmark| {
        benchmark.iter(|| {
            execute_chunk_of_transfers(
                sender_account,
                &mut random_generator,
                &accounts,
                nonce_manager,
                chain_info,
                executor,
            );
            sender_account = (sender_account + CHUNK_SIZE) % accounts.len();
        })
    });
}

fn execute_chunk_of_transfers(
    sender_account: usize,
    random_generator: &mut rand::rngs::StdRng,
    accounts: &[ContractAddress],
    nonce_manager: &mut NonceManager,
    chain_info: &ChainInfo,
    executor: &mut TransactionExecutor<DictStateReader>,
) {
    let mut chunk: Vec<Transaction> = Vec::with_capacity(CHUNK_SIZE);
    let mut recipient_account = random_generator.gen::<usize>() % accounts.len();
    for _ in 0..CHUNK_SIZE {
        let account_tx = generate_transfer(
            accounts,
            sender_account,
            recipient_account,
            nonce_manager,
            chain_info,
        );
        chunk.push(Transaction::AccountTransaction(account_tx));
        recipient_account = random_generator.gen::<usize>() % accounts.len();
    }
    executor.execute_txs(chunk.as_slice(), CHARGE_FEE);
}

fn generate_transfer(
    accounts: &[ContractAddress],
    sender_account: usize,
    recipient_account: usize,
    nonce_manager: &mut NonceManager,
    chain_info: &ChainInfo,
) -> AccountTransaction {
    let sender_address = accounts[sender_account];
    let recipient_account_address = accounts[recipient_account];
    let nonce = nonce_manager.next(sender_address);

    let entry_point_selector =
        selector_from_name(blockifier::transaction::constants::TRANSFER_ENTRY_POINT_NAME);
    let contract_address = match TRANSACTION_VERSION {
        TransactionVersion::ONE => *chain_info.fee_token_addresses.eth_fee_token_address.0.key(),
        TransactionVersion::THREE => *chain_info.fee_token_addresses.strk_fee_token_address.0.key(),
        _ => panic!("Unsupported transaction version: {TRANSACTION_VERSION:?}"),
    };

    let execute_calldata = calldata![
        contract_address,                   // Contract address.
        entry_point_selector.0,             // EP selector.
        stark_felt!(3_u8),                  // Calldata length.
        *recipient_account_address.0.key(), // Calldata: recipient.
        stark_felt!(1_u8),                  // Calldata: lsb amount.
        stark_felt!(0_u8)                   // Calldata: msb amount.
    ];

    let tx = invoke_tx(invoke_tx_args! {
        max_fee: Fee(MAX_FEE),
        sender_address,
        calldata: execute_calldata,
        version: TRANSACTION_VERSION,
        nonce,
    });
    AccountTransaction::Invoke(tx)
}

criterion_group!(benches, transfers_benchmark);
criterion_main!(benches);
