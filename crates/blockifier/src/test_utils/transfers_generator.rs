use std::iter::Cycle;
use std::ops::Range;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use starknet_api::core::ContractAddress;
use starknet_api::transaction::{Calldata, Fee, TransactionVersion};
use starknet_api::{calldata, felt};
use starknet_types_core::felt::Felt;

use crate::abi::abi_utils::selector_from_name;
use crate::blockifier::config::{ConcurrencyConfig, TransactionExecutorConfig};
use crate::blockifier::transaction_executor::TransactionExecutor;
use crate::context::{BlockContext, ChainInfo};
use crate::invoke_tx_args;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::invoke::invoke_tx;
use crate::test_utils::{CairoVersion, NonceManager, BALANCE, MAX_FEE};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants::TRANSFER_ENTRY_POINT_NAME;
use crate::transaction::transaction_execution::Transaction;

const N_ACCOUNTS: u16 = 10000;
const N_TXS: usize = 1000;
const CHARGE_FEE: bool = true;
const CAIRO_VERSION: CairoVersion = CairoVersion::Cairo0;
const TRANSACTION_VERSION: TransactionVersion = TransactionVersion(Felt::THREE);
const RECIPIENT_ITERATOR_TYPE: RecipientIteratorType = RecipientIteratorType::RoundRobin;
#[cfg(feature = "concurrency")]
const CONCURRENCY_MODE: bool = true;
#[cfg(not(feature = "concurrency"))]
const CONCURRENCY_MODE: bool = false;
const N_WORKERS: usize = 4;
const CHUNK_SIZE: usize = 100;

pub struct TransfersGeneratorConfig {
    pub n_accounts: u16,
    pub balance: u128,
    pub max_fee: u128,
    pub n_txs: usize,
    pub charge_fee: bool,
    pub cairo_version: CairoVersion,
    pub transaction_version: TransactionVersion,
    pub recipient_iterator_type: IndexIteratorType,
    pub concurrency_config: ConcurrencyConfig,
}

impl Default for TransfersGeneratorConfig {
    fn default() -> Self {
        Self {
            n_accounts: N_ACCOUNTS,
            balance: BALANCE * 1000,
            max_fee: MAX_FEE,
            n_txs: N_TXS,
            charge_fee: CHARGE_FEE,
            cairo_version: CAIRO_VERSION,
            transaction_version: TRANSACTION_VERSION,
            recipient_iterator_type: RECIPIENT_ITERATOR_TYPE,
            concurrency_config: ConcurrencyConfig {
                enabled: CONCURRENCY_MODE,
                n_workers: N_WORKERS,
                chunk_size: CHUNK_SIZE,
            },
        }
    }
}

#[derive(Clone, Copy)]
pub enum IndexIteratorType {
    Random(u64),
    RoundRobin,
    DisjointFromSenders,
}

pub enum IndexIterator {
    Random(Box<RandomIndexIterator>),
    Consecutive(Cycle<Range<usize>>),
}

impl IndexIterator {
    fn new_recipient(n_indices: usize, iterator_type: IndexIteratorType) -> Self {
        match iterator_type {
            IndexIteratorType::Random(seed) => {
                Self::Random(Box::new(RandomIndexIterator::new(n_indices, seed)))
            }
            IndexIteratorType::RoundRobin => {
                let mut iterator = (0..n_indices).cycle();
                // Skip the first element to make the first sender different from the first
                // recipient.
                iterator.next();
                Self::Consecutive(iterator)
            }
            IndexIteratorType::DisjointFromSenders => {
                let iterator = (0..n_indices).cycle();
                Self::Consecutive(iterator)
            }
        }
    }

    fn new_sender(n_indices: usize) -> Self {
        Self::Consecutive((0..n_indices).cycle())
    }
}

impl Iterator for IndexIterator {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Random(random_iterator) => random_iterator.next(),
            Self::Consecutive(iterator) => iterator.next(),
        }
    }
}

pub struct RandomIndexIterator {
    n_indices: usize,
    random_generator: StdRng,
}

impl RandomIndexIterator {
    pub fn new(n_indices: usize, seed: u64) -> Self {
        let random_generator = StdRng::seed_from_u64(seed);
        Self { n_indices, random_generator }
    }
}

impl Iterator for RandomIndexIterator {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.random_generator.gen_range(0..self.n_indices);
        Some(index)
    }
}

pub struct TransfersGenerator {
    sender_addresses: Vec<ContractAddress>,
    recipient_addresses: Option<Vec<ContractAddress>>,
    sender_iterator: IndexIterator,
    recipient_iterator: IndexIterator,
    chain_info: ChainInfo,
    executor: TransactionExecutor<DictStateReader>,
    nonce_manager: NonceManager,
    config: TransfersGeneratorConfig,
}

impl TransfersGenerator {
    pub fn new(recipient_iterator_kind: RecipientIteratorKind) -> Self {
        let account_contract = FeatureContract::AccountWithoutValidations(config.cairo_version);
        let executor_config = TransactionExecutorConfig::create_for_testing();
        let block_context = BlockContext::create_for_account_testing();
        let chain_info = block_context.chain_info().clone();
        let state =
            test_state(&chain_info, config.balance, &[(account_contract, config.n_accounts)]);
        let executor_config =
            TransactionExecutorConfig { concurrency_config: config.concurrency_config.clone() };
        let executor = TransactionExecutor::new(state, block_context, executor_config);
        let sender_addresses = (0..config.n_accounts)
            .map(|instance_id| account_contract.get_instance_address(instance_id))
            .collect::<Vec<_>>();

        // Generate the recipient addresses, if they are not the same as the sender addresses.
        let recipient_addresses = match config.recipient_iterator_type {
            IndexIteratorType::DisjointFromSenders => Some(
                (config.n_accounts..2 * config.n_accounts)
                    .map(|instance_id| account_contract.get_instance_address(instance_id))
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        };

        let nonce_manager = NonceManager::default();
        let n_indices = usize::from(config.n_accounts);
        let sender_iterator = IndexIterator::new_sender(n_indices);
        let recipient_iterator =
            IndexIterator::new_recipient(n_indices, config.recipient_iterator_type);
        Self {
            sender_addresses,
            recipient_addresses,
            sender_iterator,
            recipient_iterator,
            chain_info,
            executor,
            nonce_manager,
            config,
        }
    }

    pub fn execute_transfers(&mut self) {
        let mut txs: Vec<Transaction> = Vec::with_capacity(self.config.n_txs);
        for _ in 0..self.config.n_txs {
            let sender_address = self.sender_addresses[self.sender_iterator.next().unwrap()];
            let recipient_address =
                self.recipient_addresses.as_ref().unwrap_or(&self.sender_addresses)
                    [self.recipient_iterator.next().unwrap()];
            let account_tx = self.generate_transfer(sender_address, recipient_address);
            txs.push(Transaction::AccountTransaction(account_tx));
        }
        let results = self.executor.execute_txs(&txs);
        assert_eq!(results.len(), self.config.n_txs);
        for result in results {
            assert!(!result.unwrap().is_reverted());
        }
        // TODO(Avi, 01/06/2024): Run the same transactions concurrently on a new state and compare
        // the state diffs.
    }

    pub fn generate_transfer(
        &mut self,
        sender_address: ContractAddress,
        recipient_address: ContractAddress,
    ) -> AccountTransaction {
        let nonce = self.nonce_manager.next(sender_address);

        let entry_point_selector = selector_from_name(TRANSFER_ENTRY_POINT_NAME);
        let contract_address = if self.config.transaction_version == TransactionVersion::ONE {
            *self.chain_info.fee_token_addresses.eth_fee_token_address.0.key()
        } else if self.config.transaction_version == TransactionVersion::THREE {
            *self.chain_info.fee_token_addresses.strk_fee_token_address.0.key()
        } else {
            panic!("Unsupported transaction version: {TRANSACTION_VERSION:?}")
        };

        let execute_calldata = calldata![
            contract_address,           // Contract address.
            entry_point_selector.0,     // EP selector.
            felt!(3_u8),                // Calldata length.
            *recipient_address.0.key(), // Calldata: recipient.
            felt!(1_u8),                // Calldata: lsb amount.
            felt!(0_u8)                 // Calldata: msb amount.
        ];

        let tx = invoke_tx(invoke_tx_args! {
            max_fee: Fee(self.config.max_fee),
            sender_address,
            calldata: execute_calldata,
            version: self.config.transaction_version,
            nonce,
        });
        AccountTransaction::Invoke(tx)
    }
}

impl Default for TransfersGenerator {
    fn default() -> Self {
        Self::new(TransfersGeneratorConfig::default())
    }
}
