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
const STREAM_SIZE: usize = 1000;
const RANDOMIZATION_SEED: u64 = 0;
const TRANSACTION_VERSION: TransactionVersion = TransactionVersion(Felt::THREE);
#[cfg(feature = "concurrency")]
const CONCURRENCY_MODE: bool = true;
#[cfg(not(feature = "concurrency"))]
const CONCURRENCY_MODE: bool = false;
const N_WORKERS: usize = 4;
const CHUNK_SIZE: usize = 100;

pub enum RecipientGeneratorType {
    Random,
    RoundRobin,
    DisjointFromSenders,
}

pub struct TransfersGenerator {
    account_addresses: Vec<ContractAddress>,
    chain_info: ChainInfo,
    executor: TransactionExecutor<DictStateReader>,
    nonce_manager: NonceManager,
    sender_index: usize,
    recipient_generator_type: RecipientGeneratorType,
    random_recipient_generator: Option<StdRng>,
    recipient_addresses: Option<Vec<ContractAddress>>,
}

impl TransfersGenerator {
    pub fn new(recipient_generator_type: RecipientGeneratorType) -> Self {
        let account_contract = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo0);
        let block_context = BlockContext::create_for_account_testing();
        let chain_info = block_context.chain_info().clone();
        let state = test_state(&chain_info, BALANCE * 1000, &[(account_contract, N_ACCOUNTS)]);
        let concurrency_config = ConcurrencyConfig {
            enabled: CONCURRENCY_MODE,
            n_workers: N_WORKERS,
            chunk_size: CHUNK_SIZE,
        };
        let executor_config = TransactionExecutorConfig { concurrency_config };
        let executor = TransactionExecutor::new(state, block_context, executor_config);
        let account_addresses = (0..N_ACCOUNTS)
            .map(|instance_id| account_contract.get_instance_address(instance_id))
            .collect::<Vec<_>>();
        let nonce_manager = NonceManager::default();
        let mut recipient_addresses = None;
        let mut random_recipient_generator = None;
        match recipient_generator_type {
            RecipientGeneratorType::Random => {
                // Use a random generator to get the next recipient.
                random_recipient_generator = Some(StdRng::seed_from_u64(RANDOMIZATION_SEED));
            }
            RecipientGeneratorType::RoundRobin => {
                // Use the next account after the sender in the list as the recipient.
            }
            RecipientGeneratorType::DisjointFromSenders => {
                // Use a disjoint set of accounts as recipients. The index of the recipient is the
                // same as the index of the sender.
                recipient_addresses = Some(
                    (N_ACCOUNTS..2 * N_ACCOUNTS)
                        .map(|instance_id| account_contract.get_instance_address(instance_id))
                        .collect::<Vec<_>>(),
                );
            }
        };
        Self {
            account_addresses,
            chain_info,
            executor,
            nonce_manager,
            sender_index: 0,
            recipient_generator_type,
            random_recipient_generator,
            recipient_addresses,
        }
    }

    pub fn get_next_recipient(&mut self) -> ContractAddress {
        match self.recipient_generator_type {
            RecipientGeneratorType::Random => {
                let random_recipient_generator = self.random_recipient_generator.as_mut().unwrap();
                let recipient_index =
                    random_recipient_generator.gen_range(0..self.account_addresses.len());
                self.account_addresses[recipient_index]
            }
            RecipientGeneratorType::RoundRobin => {
                let recipient_index = (self.sender_index + 1) % self.account_addresses.len();
                self.account_addresses[recipient_index]
            }
            RecipientGeneratorType::DisjointFromSenders => {
                self.recipient_addresses.as_ref().unwrap()[self.sender_index]
            }
        }
    }

    pub fn execute_transfers_stream(&mut self) {
        let mut tx_stream: Vec<Transaction> = Vec::with_capacity(STREAM_SIZE);
        for _ in 0..STREAM_SIZE {
            let sender_address = self.account_addresses[self.sender_index];
            let recipient_address = self.get_next_recipient();
            self.sender_index = (self.sender_index + 1) % self.account_addresses.len();

            let account_tx = self.generate_transfer(sender_address, recipient_address);
            tx_stream.push(Transaction::AccountTransaction(account_tx));
        }
        let results = self.executor.execute_txs(&tx_stream);
        assert_eq!(results.len(), STREAM_SIZE);
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
        let contract_address = if TRANSACTION_VERSION == TransactionVersion::ONE {
            *self.chain_info.fee_token_addresses.eth_fee_token_address.0.key()
        } else if TRANSACTION_VERSION == TransactionVersion::THREE {
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
            max_fee: Fee(MAX_FEE),
            sender_address,
            calldata: execute_calldata,
            version: TRANSACTION_VERSION,
            nonce,
        });
        AccountTransaction::Invoke(tx)
    }
}

impl Default for TransfersGenerator {
    fn default() -> Self {
        Self::new(RecipientGeneratorType::RoundRobin)
    }
}
