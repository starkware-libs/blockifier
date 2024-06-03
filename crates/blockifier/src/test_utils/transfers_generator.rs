use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, Fee, TransactionVersion};
use starknet_api::{calldata, stark_felt};

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
const RANDOMIZATION_SEED: u64 = 0;
const CHARGE_FEE: bool = true;
const CAIRO_VERSION: CairoVersion = CairoVersion::Cairo0;
const TRANSACTION_VERSION: TransactionVersion = TransactionVersion(StarkFelt::THREE);
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
    pub randomization_seed: u64,
    pub charge_fee: bool,
    pub cairo_version: CairoVersion,
    pub transaction_version: TransactionVersion,
    pub recipient_iterator_type: RecipientIteratorType,
    pub concurrency_config: ConcurrencyConfig,
}

impl Default for TransfersGeneratorConfig {
    fn default() -> Self {
        Self {
            n_accounts: N_ACCOUNTS,
            balance: BALANCE * 1000,
            max_fee: MAX_FEE,
            n_txs: N_TXS,
            randomization_seed: RANDOMIZATION_SEED,
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

pub enum RecipientIteratorType {
    Random,
    RoundRobin,
    DisjointFromSenders,
}

pub struct RandomRecipientIterator {
    account_addresses: Vec<ContractAddress>,
    random_generator: StdRng,
}

impl RandomRecipientIterator {
    pub fn new(account_addresses: Vec<ContractAddress>, seed: u64) -> Self {
        let random_generator = StdRng::seed_from_u64(seed);
        Self { account_addresses, random_generator }
    }
}

impl Iterator for RandomRecipientIterator {
    type Item = ContractAddress;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.random_generator.gen::<usize>() % self.account_addresses.len();
        Some(self.account_addresses[index])
    }
}

pub struct RoundRobinRecipientIterator {
    account_addresses: Vec<ContractAddress>,
    index: usize,
}

impl Iterator for RoundRobinRecipientIterator {
    type Item = ContractAddress;

    fn next(&mut self) -> Option<Self::Item> {
        let current_index = self.index;
        self.index = (self.index + 1) % self.account_addresses.len();
        Some(self.account_addresses[current_index])
    }
}

pub struct TransfersGenerator {
    account_addresses: Vec<ContractAddress>,
    chain_info: ChainInfo,
    executor: TransactionExecutor<DictStateReader>,
    nonce_manager: NonceManager,
    recipient_iterator: Box<dyn Iterator<Item = ContractAddress>>,
    sender_index: usize,
    config: TransfersGeneratorConfig,
}

impl TransfersGenerator {
    pub fn new(config: TransfersGeneratorConfig) -> Self {
        let account_contract = FeatureContract::AccountWithoutValidations(config.cairo_version);
        let block_context = BlockContext::create_for_account_testing_with_concurrency_mode(
            config.concurrency_config.enabled,
        );
        let chain_info = block_context.chain_info().clone();
        let state =
            test_state(&chain_info, config.balance, &[(account_contract, config.n_accounts)]);
        let executor_config =
            TransactionExecutorConfig { concurrency_config: config.concurrency_config.clone() };
        let executor = TransactionExecutor::new(state, block_context, executor_config);
        let account_addresses = (0..config.n_accounts)
            .map(|instance_id| account_contract.get_instance_address(instance_id))
            .collect::<Vec<_>>();
        let nonce_manager = NonceManager::default();
        let first_sender_index = 0;
        let recipient_iterator: Box<dyn Iterator<Item = ContractAddress>> =
            match config.recipient_iterator_type {
                RecipientIteratorType::Random => Box::new(RandomRecipientIterator::new(
                    account_addresses.clone(),
                    config.randomization_seed,
                )),
                RecipientIteratorType::RoundRobin => {
                    // Each sender `i` sends to recipient `i+1`.
                    let first_recipient_index = first_sender_index + 1;
                    Box::new(RoundRobinRecipientIterator {
                        account_addresses: account_addresses.clone(),
                        index: first_recipient_index,
                    })
                }
                RecipientIteratorType::DisjointFromSenders => {
                    // Create a set of recipient addresses disjoint from the senders. Each sender
                    // `i` sends to recipient `i`.
                    let first_recipient_index = 0;
                    let account_addresses = (config.n_accounts..2 * config.n_accounts)
                        .map(|instance_id| account_contract.get_instance_address(instance_id))
                        .collect::<Vec<_>>();
                    Box::new(RoundRobinRecipientIterator {
                        account_addresses,
                        index: first_recipient_index,
                    })
                }
            };
        Self {
            account_addresses,
            chain_info,
            executor,
            nonce_manager,
            recipient_iterator,
            sender_index: first_sender_index,
            config,
        }
    }

    pub fn execute_transfers(&mut self) {
        let mut txs: Vec<Transaction> = Vec::with_capacity(self.config.n_txs);
        for _ in 0..self.config.n_txs {
            let sender_address = self.account_addresses[self.sender_index];
            self.sender_index = (self.sender_index + 1) % self.account_addresses.len();
            let recipient_address = self.recipient_iterator.next().unwrap();

            let account_tx = self.generate_transfer(sender_address, recipient_address);
            txs.push(Transaction::AccountTransaction(account_tx));
        }
        let results = self.executor.execute_txs(&txs, self.config.charge_fee);
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
        let contract_address = match self.config.transaction_version {
            TransactionVersion::ONE => {
                *self.chain_info.fee_token_addresses.eth_fee_token_address.0.key()
            }
            TransactionVersion::THREE => {
                *self.chain_info.fee_token_addresses.strk_fee_token_address.0.key()
            }
            _ => panic!("Unsupported transaction version: {:?}", self.config.transaction_version),
        };

        let execute_calldata = calldata![
            contract_address,           // Contract address.
            entry_point_selector.0,     // EP selector.
            stark_felt!(3_u8),          // Calldata length.
            *recipient_address.0.key(), // Calldata: recipient.
            stark_felt!(1_u8),          // Calldata: lsb amount.
            stark_felt!(0_u8)           // Calldata: msb amount.
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
