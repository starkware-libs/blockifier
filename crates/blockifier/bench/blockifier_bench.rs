//! Benchmark module for the blockifier crate. It provides functionalities to benchmark
//! various aspects related to transferring between accounts, including preparation
//! and execution of transfers.
//!
//! The main benchmark function is `transfers_benchmark`, which measures the performance
//! of transfers between randomly created accounts, which are iterated over round-robin.
//!
//! Run the benchmarks using `cargo bench --bench blockifier_bench`.

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::context::BlockContext;
use blockifier::invoke_tx_args;
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::contracts::FeatureContract;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::initial_test_state::test_state;
use blockifier::test_utils::invoke::invoke_tx;
use blockifier::test_utils::{CairoVersion, NonceManager, BALANCE, MAX_FEE};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{Rng, SeedableRng};
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, Fee, TransactionVersion};
use starknet_api::{calldata, stark_felt};

const N_ACCOUNTS: u16 = 10000;
const RANDOMIZATION_SEED: u64 = 0;
const CHARGE_FEE: bool = false;
const RUN_VALIDATION: bool = false;
const TRANSACTION_VERSION: TransactionVersion = TransactionVersion(StarkFelt::ONE);

pub fn transfers_benchmark(c: &mut Criterion) {
    let account_contract = FeatureContract::AccountWithLongValidate(CairoVersion::Cairo0);
    let block_context = &BlockContext::create_for_account_testing();
    let mut state =
        test_state(block_context.chain_info(), BALANCE * 1000, &[(account_contract, N_ACCOUNTS)]);
    let accounts = (0..N_ACCOUNTS)
        .map(|instance_id| account_contract.get_instance_address(instance_id))
        .collect::<Vec<_>>();
    let nonce_manager = &mut NonceManager::default();

    let mut sender_account = 0;
    let mut random_generator = rand::rngs::StdRng::seed_from_u64(RANDOMIZATION_SEED);
    let mut recipient_account = random_generator.gen::<usize>() % accounts.len();
    // Create a benchmark group called "transfers", which iterates over the accounts round-robin
    // and performs transfers.
    c.bench_function("transfers", |benchmark| {
        benchmark.iter(|| {
            do_transfer(
                sender_account,
                recipient_account,
                &accounts,
                nonce_manager,
                block_context,
                &mut state,
            );
            sender_account = (sender_account + 1) % accounts.len();
            recipient_account = random_generator.gen::<usize>() % accounts.len();
        })
    });
}

fn do_transfer(
    sender_account: usize,
    recipient_account: usize,
    accounts: &[ContractAddress],
    nonce_manager: &mut NonceManager,
    block_context: &BlockContext,
    state: &mut CachedState<DictStateReader>,
) {
    let sender_address = accounts[sender_account];
    let recipient_account_address = accounts[recipient_account];
    let nonce = nonce_manager.next(sender_address);

    let entry_point_selector =
        selector_from_name(blockifier::transaction::constants::TRANSFER_ENTRY_POINT_NAME);
    let contract_address = match TRANSACTION_VERSION {
        TransactionVersion::ONE => {
            *block_context.chain_info().fee_token_addresses.eth_fee_token_address.0.key()
        }
        TransactionVersion::THREE => {
            *block_context.chain_info().fee_token_addresses.strk_fee_token_address.0.key()
        }
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
    let account_tx = AccountTransaction::Invoke(tx);
    let charge_fee = CHARGE_FEE;
    let validate = RUN_VALIDATION;
    account_tx.execute(state, block_context, charge_fee, validate, None).unwrap();
}

criterion_group!(benches, transfers_benchmark);
criterion_main!(benches);
