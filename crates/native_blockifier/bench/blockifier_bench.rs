//! Benchmark for the blockifier crate. Run using `cargo bench --bench blockifier_bench`.

use std::collections::HashMap;

use blockifier::abi::abi_utils::{get_storage_var_address, selector_from_name};
use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClassV0;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::State;
use blockifier::test_utils::{
    deploy_account_tx_with_salt, invoke_tx, DictStateReader, ACCOUNT_CONTRACT_PATH, BALANCE,
    ERC20_CONTRACT_PATH, MAX_FEE, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_ERC20_CONTRACT_CLASS_HASH,
};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use criterion::{criterion_group, criterion_main, Criterion};
use starknet_api::core::{ClassHash, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, Fee, InvokeTransaction, InvokeTransactionV1,
};
use starknet_api::{calldata, stark_felt};

const N_ACCOUNTS: usize = 10;

fn create_state() -> CachedState<DictStateReader> {
    let block_context = BlockContext::create_for_account_testing();

    // Declare all the needed contracts.
    let test_account_class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let test_erc20_class_hash = ClassHash(stark_felt!(TEST_ERC20_CONTRACT_CLASS_HASH));
    let class_hash_to_class = HashMap::from([
        (test_account_class_hash, ContractClassV0::from_file(ACCOUNT_CONTRACT_PATH).into()),
        (test_erc20_class_hash, ContractClassV0::from_file(ERC20_CONTRACT_PATH).into()),
    ]);
    // Deploy the erc20 contract.
    let test_erc20_address = block_context.fee_token_address;
    let address_to_class_hash = HashMap::from([(test_erc20_address, test_erc20_class_hash)]);

    CachedState::new(DictStateReader {
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
    c.bench_function("transfers", |b| {
        b.iter(|| {
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
        *block_context.fee_token_address.0.key(), // Contract address.
        entry_point_selector.0,                   // EP selector.
        stark_felt!(3_u8),                        // Calldata length.
        *recipient_account_address.0.key(),       // Calldata: recipient.
        stark_felt!(1_u8),                        // Calldata: lsb amount.
        stark_felt!(0_u8)                         // Calldata: msb amount.
    ];

    let tx = invoke_tx(execute_calldata, sender_account_address, Fee(MAX_FEE), None);
    let account_tx = AccountTransaction::Invoke(InvokeTransaction::V1(InvokeTransactionV1 {
        nonce: Nonce(stark_felt!(nonce)),
        ..tx
    }));
    account_tx.execute(state, block_context).unwrap();
}

fn prepare_accounts(
    state: &mut CachedState<DictStateReader>,
    block_context: &BlockContext,
) -> (Vec<ContractAddress>, Vec<u64>) {
    // Prepare accounts.
    let mut addresses = vec![];
    let mut nonces = vec![];
    for i in 0..N_ACCOUNTS {
        // Deploy an account contract.
        let deploy_account_tx = deploy_account_tx_with_salt(
            TEST_ACCOUNT_CONTRACT_CLASS_HASH,
            Fee(MAX_FEE),
            None,
            ContractAddressSalt(stark_felt!(i as u64)),
            None,
        );

        // Update the balance of the account.
        let deployed_account_address = deploy_account_tx.contract_address;
        addresses.push(deployed_account_address);
        nonces.push(1_u64);
        let deployed_account_balance_key =
            get_storage_var_address("ERC20_balances", &[*deployed_account_address.0.key()])
                .unwrap();
        state.set_storage_at(
            block_context.fee_token_address,
            deployed_account_balance_key,
            stark_felt!(BALANCE * 1000),
        );

        let account_tx = AccountTransaction::DeployAccount(deploy_account_tx);
        account_tx.execute(state, block_context).unwrap();
    }
    (addresses, nonces)
}

criterion_group!(benches, transfers_benchmark);
criterion_main!(benches);
