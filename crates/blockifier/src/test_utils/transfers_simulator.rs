use rand::{Rng, SeedableRng};
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, Fee, TransactionVersion};
use starknet_api::{calldata, stark_felt};

use crate::abi::abi_utils::selector_from_name;
use crate::blockifier::config::TransactionExecutorConfig;
use crate::blockifier::transaction_executor::TransactionExecutor;
use crate::bouncer::BouncerConfig;
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
const CHUNK_SIZE: usize = 10;
const RANDOMIZATION_SEED: u64 = 0;
const CHARGE_FEE: bool = false;
const TRANSACTION_VERSION: TransactionVersion = TransactionVersion(StarkFelt::ONE);

struct RandomGenerator {
    generator: rand::rngs::StdRng,
}

impl RandomGenerator {
    fn new(seed: u64) -> Self {
        Self { generator: rand::rngs::StdRng::seed_from_u64(seed) }
    }

    fn next(&mut self) -> usize {
        self.generator.gen::<usize>()
    }
}

enum RecipientGenerator {
    Random(RandomGenerator, Vec<ContractAddress>),
    Sequential(usize, Vec<ContractAddress>),
}
impl RecipientGenerator {
    fn next(&mut self) -> ContractAddress {
        match self {
            RecipientGenerator::Random(generator, accounts) => {
                accounts[generator.next() % accounts.len()]
            }
            RecipientGenerator::Sequential(index, accounts) => {
                *index += 1 % accounts.len();
                accounts[*index]
            }
        }
    }
}
pub struct TransfersSimulator {
    accounts: Vec<ContractAddress>,
    chain_info: ChainInfo,
    executor: TransactionExecutor<DictStateReader>,
    nonce_manager: NonceManager,
    recipient_generator: RecipientGenerator,
    sender_index: usize,
}

impl TransfersSimulator {
    pub fn new(random_recipients: bool, disjoint_recipients: bool) -> Self {
        let account_contract = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo0);
        let block_context = BlockContext::create_for_account_testing_with_concurrency_mode(true);
        let chain_info = block_context.chain_info().clone();
        let state = test_state(&chain_info, BALANCE * 1000, &[(account_contract, N_ACCOUNTS)]);
        // TODO(Avi, 20/05/2024): Enable concurrency.
        let executor_config = TransactionExecutorConfig::default();
        let executor =
            TransactionExecutor::new(state, block_context, BouncerConfig::max(), executor_config);
        let accounts = (0..N_ACCOUNTS)
            .map(|instance_id| account_contract.get_instance_address(instance_id))
            .collect::<Vec<_>>();
        let nonce_manager = NonceManager::default();
        let recipient_accounts = if disjoint_recipients {
            (N_ACCOUNTS..2 * N_ACCOUNTS)
                .map(|instance_id| account_contract.get_instance_address(instance_id))
                .collect::<Vec<_>>()
        } else {
            accounts.clone()
        };
        let recipient_generator = if random_recipients {
            let random_generator = RandomGenerator::new(RANDOMIZATION_SEED);
            RecipientGenerator::Random(random_generator, recipient_accounts)
        } else {
            let index = 1;
            RecipientGenerator::Sequential(index, recipient_accounts)
        };
        Self { accounts, chain_info, executor, nonce_manager, recipient_generator, sender_index: 0 }
    }

    pub fn execute_chunk_of_transfers(&mut self) {
        let mut chunk: Vec<Transaction> = Vec::with_capacity(CHUNK_SIZE);
        for _ in 0..CHUNK_SIZE {
            let account_tx = self.generate_transfer();
            chunk.push(Transaction::AccountTransaction(account_tx));
        }
        let results = self.executor.execute_txs(&chunk, CHARGE_FEE);
        assert_eq!(results.len(), CHUNK_SIZE);
        for result in results {
            assert!(!result.unwrap().is_reverted());
        }
    }

    pub fn generate_transfer(&mut self) -> AccountTransaction {
        let sender_address = self.accounts[self.sender_index];
        self.sender_index = (self.sender_index + 1) % self.accounts.len();
        let recipient_address = self.recipient_generator.next();
        let nonce = self.nonce_manager.next(sender_address);

        let entry_point_selector = selector_from_name(TRANSFER_ENTRY_POINT_NAME);
        let contract_address = match TRANSACTION_VERSION {
            TransactionVersion::ONE => {
                *self.chain_info.fee_token_addresses.eth_fee_token_address.0.key()
            }
            TransactionVersion::THREE => {
                *self.chain_info.fee_token_addresses.strk_fee_token_address.0.key()
            }
            _ => panic!("Unsupported transaction version: {TRANSACTION_VERSION:?}"),
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
            max_fee: Fee(MAX_FEE),
            sender_address,
            calldata: execute_calldata,
            version: TRANSACTION_VERSION,
            nonce,
        });
        AccountTransaction::Invoke(tx)
    }
}

impl Default for TransfersSimulator {
    fn default() -> Self {
        let random_recipients = false;
        let disjoint_recipients = false;
        Self::new(random_recipients, disjoint_recipients)
    }
}
