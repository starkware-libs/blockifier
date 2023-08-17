//! Benchmark module for the blockifier crate. It provides functionalities to benchmark
//! various aspects related to transferring between accounts, including preparation
//! and execution of transfers.
//!
//! The main benchmark function is `transfers_benchmark`, which measures the performance
//! of transfers between randomly created accounts, which are iterated over round-robin.
//!
//! Run the benchmarks using `cargo bench --bench blockifier_bench`.

use std::collections::HashMap;

use blockifier::abi::abi_utils::{get_storage_var_address, selector_from_name};
use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClassV0;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::State;
use blockifier::test_utils::{
    deploy_account_tx_with_salt, invoke_tx, DictStateReader, NonceManager,
    ACCOUNT_CONTRACT_CAIRO0_PATH, BALANCE, ERC20_CONTRACT_PATH, MAX_FEE,
    TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_ERC20_CONTRACT_CLASS_HASH,
};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::transactions::{ExecutableTransaction, InvokeTransaction};
use criterion::{criterion_group, criterion_main, Criterion};
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, Fee, InvokeTransaction as StarknetInvokeTransaction,
    InvokeTransactionV1, TransactionHash,
};
use starknet_api::{calldata, stark_felt};

const N_ACCOUNTS: usize = 10000;

fn create_state() -> CachedState<DictStateReader> {
    let block_context = BlockContext::create_for_account_testing();

    // Declare all the needed contracts.
    let test_account_class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let test_erc20_class_hash = ClassHash(stark_felt!(TEST_ERC20_CONTRACT_CLASS_HASH));
    let class_hash_to_class = HashMap::from([
        (test_account_class_hash, ContractClassV0::from_file(ACCOUNT_CONTRACT_CAIRO0_PATH).into()),
        (test_erc20_class_hash, ContractClassV0::from_file(ERC20_CONTRACT_PATH).into()),
    ]);
    // Deploy the ERC20 contract.
    let test_erc20_address = block_context.deprecated_fee_token_address;
    let address_to_class_hash = HashMap::from([(test_erc20_address, test_erc20_class_hash)]);

    CachedState::from(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        ..Default::default()
    })
}

pub fn transfers_benchmark(c: &mut Criterion) {
    let mut state = create_state();
    let block_context = &BlockContext::create_for_account_testing();
    let (accounts, mut nonces) = prepare_accounts(&mut state, block_context);

    let mut sender_account = 0;
    // Create a benchmark group called "transfers", which iterates over the accounts round-robin
    // and performs transfers.
    c.bench_function("transfers", |benchmark| {
        benchmark.iter(|| {
            do_transfer(sender_account, &accounts, &mut nonces, block_context, &mut state);
            sender_account = (sender_account + 1) % accounts.len();
        })
    });
}

fn do_transfer(
    sender_account: usize,
    accounts: &[ContractAddress],
    nonces: &mut [u64],
    block_context: &BlockContext,
    state: &mut CachedState<DictStateReader>,
) {
    let n_accounts = accounts.len();
    let recipient_account = (sender_account + 1) % n_accounts;
    let sender_account_address = accounts[sender_account];
    let recipient_account_address = accounts[recipient_account];
    let nonce = nonces[sender_account];
    nonces[sender_account] += 1;

    let entry_point_selector =
        selector_from_name(blockifier::transaction::constants::TRANSFER_ENTRY_POINT_NAME);
    let execute_calldata = calldata![
        *block_context.deprecated_fee_token_address.0.key(), // Contract address.
        entry_point_selector.0,                              // EP selector.
        stark_felt!(3_u8),                                   // Calldata length.
        *recipient_account_address.0.key(),                  // Calldata: recipient.
        stark_felt!(1_u8),                                   // Calldata: lsb amount.
        stark_felt!(0_u8)                                    // Calldata: msb amount.
    ];

    let tx = invoke_tx(execute_calldata, sender_account_address, Fee(MAX_FEE), None);
    let sn_api_tx = StarknetInvokeTransaction::V1(InvokeTransactionV1 {
        nonce: Nonce(stark_felt!(nonce)),
        ..tx
    });
    let account_tx = AccountTransaction::Invoke(InvokeTransaction {
        tx: sn_api_tx,
        tx_hash: TransactionHash::default(),
    });
    let charge_fee = false;
    let validate = false;
    account_tx.execute(state, block_context, charge_fee, validate).unwrap();
}

fn prepare_accounts(
    state: &mut CachedState<DictStateReader>,
    block_context: &BlockContext,
) -> (Vec<ContractAddress>, Vec<u64>) {
    // Prepare accounts.
    let mut addresses = vec![];
    let mut nonces = vec![];
    for account_salt in 0..N_ACCOUNTS {
        // Deploy an account contract.
        let class_hash = TEST_ACCOUNT_CONTRACT_CLASS_HASH;
        let max_fee = Fee(MAX_FEE);
        let constructor_calldata = None;
        let constructor_address_salt = ContractAddressSalt(stark_felt!(account_salt as u64));
        let signature = None;
        let nonce_manager = &mut NonceManager::default();
        let deploy_account_tx = deploy_account_tx_with_salt(
            class_hash,
            max_fee,
            constructor_calldata,
            constructor_address_salt,
            signature,
            nonce_manager,
        );

        // Update the balance of the account.
        let deployed_account_address = deploy_account_tx.contract_address;
        addresses.push(deployed_account_address);
        nonces.push(1_u64);
        let deployed_account_balance_key =
            get_storage_var_address("ERC20_balances", &[*deployed_account_address.0.key()])
                .unwrap();
        state.set_storage_at(
            block_context.deprecated_fee_token_address,
            deployed_account_balance_key,
            stark_felt!(BALANCE * 1000),
        );

        let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);
        let charge_fee = false;
        let validate = false;
        account_tx.execute(state, block_context, charge_fee, validate).unwrap();
    }

    (addresses, nonces)
}

criterion_group!(benches, transfers_benchmark);
criterion_main!(benches);
