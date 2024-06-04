use std::sync::{Arc, Mutex};

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use itertools::FoldWhile::{Continue, Done};
use itertools::Itertools;
use starknet_api::core::ClassHash;
use thiserror::Error;

use crate::blockifier::config::TransactionExecutorConfig;
use crate::bouncer::{Bouncer, BouncerWeights};
#[cfg(feature = "concurrency")]
use crate::concurrency::worker_logic::WorkerExecutor;
use crate::context::BlockContext;
use crate::execution::call_info::CallInfo;
use crate::fee::actual_cost::TransactionReceipt;
use crate::state::cached_state::{CachedState, CommitmentStateDiff, TransactionalState};
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::TransactionExecutionInfo;
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::{ExecutableTransaction, ValidatableTransaction};

#[cfg(test)]
#[path = "transaction_executor_test.rs"]
pub mod transaction_executor_test;

pub const BLOCK_STATE_ACCESS_ERR: &str = "Error: The block state should be `Some`.";

#[derive(Debug, Error)]
pub enum TransactionExecutorError {
    #[error("Transaction cannot be added to the current block, block capacity reached.")]
    BlockFull,
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error(transparent)]
    TransactionExecutionError(#[from] TransactionExecutionError),
}

pub type TransactionExecutorResult<T> = Result<T, TransactionExecutorError>;
pub type VisitedSegmentsMapping = Vec<(ClassHash, Vec<usize>)>;

// TODO(Gilad): make this hold TransactionContext instead of BlockContext.
pub struct TransactionExecutor<S: StateReader> {
    pub block_context: BlockContext,
    pub bouncer: Bouncer,
    // Note: this config must not affect the execution result (e.g. state diff and traces).
    pub config: TransactionExecutorConfig,

    // State-related fields.
    // The transaction executor operates at the block level. In concurrency mode, it moves the
    // block state to the worker executor - operating at the chunk level - and gets it back after
    // committing the chunk. The block state is wrapped with an Option<_> to allow setting it to
    // `None` while it is moved to the worker executor.
    pub block_state: Option<CachedState<S>>,
}

impl<S: StateReader> TransactionExecutor<S> {
    pub fn new(
        block_state: CachedState<S>,
        block_context: BlockContext,
        config: TransactionExecutorConfig,
    ) -> Self {
        log::debug!("Initializing Transaction Executor...");
        let bouncer_config = block_context.bouncer_config.clone();
        // Note: the state might not be empty even at this point; it is the creator's
        // responsibility to tune the bouncer according to pre and post block process.
        let tx_executor = Self {
            block_context,
            bouncer: Bouncer::new(bouncer_config),
            config,
            block_state: Some(block_state),
        };
        log::debug!("Initialized Transaction Executor.");

        tx_executor
    }

    /// Executes the given transaction on the state maintained by the executor.
    /// Returns the execution result (info or error) if there is room for the transaction;
    /// Otherwise, returns BlockFull error.
    pub fn execute(
        &mut self,
        tx: &Transaction,
        charge_fee: bool,
    ) -> TransactionExecutorResult<TransactionExecutionInfo> {
        let mut transactional_state = TransactionalState::create_transactional(
            self.block_state.as_mut().expect(BLOCK_STATE_ACCESS_ERR),
        );
        let validate = true;

        let tx_execution_result =
            tx.execute_raw(&mut transactional_state, &self.block_context, charge_fee, validate);
        match tx_execution_result {
            Ok(tx_execution_info) => {
                let tx_state_changes_keys =
                    transactional_state.get_actual_state_changes()?.into_keys();
                self.bouncer.try_update(
                    &transactional_state,
                    &tx_state_changes_keys,
                    &tx_execution_info.summarize(),
                    &tx_execution_info.actual_resources,
                )?;
                transactional_state.commit();
                Ok(tx_execution_info)
            }
            Err(error) => {
                transactional_state.abort();
                Err(TransactionExecutorError::TransactionExecutionError(error))
            }
        }
    }

    pub fn execute_txs_sequentially(
        &mut self,
        txs: &[Transaction],
        charge_fee: bool,
    ) -> Vec<TransactionExecutorResult<TransactionExecutionInfo>> {
        let mut results = Vec::new();
        for tx in txs {
            match self.execute(tx, charge_fee) {
                Ok(tx_execution_info) => results.push(Ok(tx_execution_info)),
                Err(TransactionExecutorError::BlockFull) => break,
                Err(error) => results.push(Err(error)),
            }
        }
        results
    }

    #[cfg(not(feature = "concurrency"))]
    pub fn execute_chunk(
        &mut self,
        chunk: &[Transaction],
        // TODO(barak, 01/08/2024): Make `charge_fee` a parameter of `WorkerExecutor`.
        _charge_fee: bool,
    ) -> Vec<TransactionExecutorResult<TransactionExecutionInfo>> {
        unimplemented!()
    }

    pub fn validate(
        &mut self,
        account_tx: &AccountTransaction,
        mut remaining_gas: u64,
    ) -> TransactionExecutorResult<(Option<CallInfo>, TransactionReceipt)> {
        let mut execution_resources = ExecutionResources::default();
        let tx_context = Arc::new(self.block_context.to_tx_context(account_tx));
        let tx_info = &tx_context.tx_info;

        // TODO(Amos, 01/12/2023): Delete this once deprecated txs call
        // PyValidator.perform_validations().
        // For fee charging purposes, the nonce-increment cost is taken into consideration when
        // calculating the fees for validation.
        // Note: This assumes that the state is reset between calls to validate.
        self.block_state
            .as_mut()
            .expect(BLOCK_STATE_ACCESS_ERR)
            .increment_nonce(tx_info.sender_address())?;

        let limit_steps_by_resources = true;
        let validate_call_info = account_tx.validate_tx(
            self.block_state.as_mut().expect(BLOCK_STATE_ACCESS_ERR),
            &mut execution_resources,
            tx_context.clone(),
            &mut remaining_gas,
            limit_steps_by_resources,
        )?;

        let tx_receipt = TransactionReceipt::from_account_tx(
            account_tx,
            &tx_context,
            &self.block_state.as_mut().expect(BLOCK_STATE_ACCESS_ERR).get_actual_state_changes()?,
            &execution_resources,
            validate_call_info.iter(),
            0,
        )?;

        Ok((validate_call_info, tx_receipt))
    }

    /// Returns the state diff, a list of contract class hash with the corresponding list of
    /// visited segment values and the block weights.
    pub fn finalize(
        &mut self,
    ) -> TransactionExecutorResult<(CommitmentStateDiff, VisitedSegmentsMapping, BouncerWeights)>
    {
        // Get the visited segments of each contract class.
        // This is done by taking all the visited PCs of each contract, and compress them to one
        // representative for each visited segment.
        let visited_segments = self
            .block_state
            .as_ref()
            .expect(BLOCK_STATE_ACCESS_ERR)
            .visited_pcs
            .iter()
            .map(|(class_hash, class_visited_pcs)| -> TransactionExecutorResult<_> {
                let contract_class = self
                    .block_state
                    .as_ref()
                    .expect(BLOCK_STATE_ACCESS_ERR)
                    .get_compiled_contract_class(*class_hash)?;
                Ok((*class_hash, contract_class.get_visited_segments(class_visited_pcs)?))
            })
            .collect::<TransactionExecutorResult<_>>()?;

        log::debug!("Final block weights: {:?}.", self.bouncer.get_accumulated_weights());
        Ok((
            self.block_state.as_mut().expect(BLOCK_STATE_ACCESS_ERR).to_state_diff()?.into(),
            visited_segments,
            *self.bouncer.get_accumulated_weights(),
        ))
    }
}

impl<S: StateReader + Send + Sync> TransactionExecutor<S> {
    /// Executes the given transactions on the state maintained by the executor.
    /// Stops if and when there is no more room in the block, and returns the executed transactions'
    /// results.
    pub fn execute_txs(
        &mut self,
        txs: &[Transaction],
        charge_fee: bool,
    ) -> Vec<TransactionExecutorResult<TransactionExecutionInfo>> {
        if !self.config.concurrency_config.enabled {
            self.execute_txs_sequentially(txs, charge_fee)
        } else {
            txs.chunks(self.config.concurrency_config.chunk_size)
                .fold_while(Vec::new(), |mut results, chunk| {
                    let chunk_results = self.execute_chunk(chunk, charge_fee);
                    if chunk_results.len() < chunk.len() {
                        // Block is full.
                        results.extend(chunk_results);
                        Done(results)
                    } else {
                        results.extend(chunk_results);
                        Continue(results)
                    }
                })
                .into_inner()
        }
    }

    #[cfg(feature = "concurrency")]
    pub fn execute_chunk(
        &mut self,
        chunk: &[Transaction],
        // TODO(barak, 01/08/2024): Make `charge_fee` a parameter of `WorkerExecutor`.
        _charge_fee: bool,
    ) -> Vec<TransactionExecutorResult<TransactionExecutionInfo>> {
        let block_state = self.block_state.take().expect("The block state should be `Some`.");

        let worker_executor_factory = Arc::new(WorkerExecutor::create_factory(
            block_state,
            chunk,
            self.block_context.clone(),
            Mutex::new(&mut self.bouncer),
        ));

        // No thread pool implementation is needed here since we already have our scheduler. The
        // initialized threads below will "busy wait" for new tasks using the `run` method until the
        // chunk execution is completed, and then they will be joined together in a for loop.
        // TODO(barak, 01/07/2024): Consider using tokio and spawn tasks that will be served by some
        // upper level tokio thread pool (Runtime in tokio terminology).
        std::thread::scope(|s| {
            for _ in 0..self.config.concurrency_config.n_workers {
                let worker_executor = Arc::clone(&worker_executor_factory);
                s.spawn(move || {
                    worker_executor.run();
                });
            }
        });

        let n_committed_txs = worker_executor_factory.scheduler.get_n_committed_txs();
        let tx_execution_results = worker_executor_factory
            .execution_outputs
            .iter()
            .fold_while(Vec::new(), |mut results, execution_output| {
                if results.len() >= n_committed_txs {
                    Done(results)
                } else {
                    let locked_execution_output = execution_output
                        .lock()
                        .expect("Failed to lock execution output.")
                        .take()
                        .expect("Output must be ready.");
                    results.push(
                        locked_execution_output.result.map_err(TransactionExecutorError::from),
                    );
                    Continue(results)
                }
            })
            .into_inner();

        let block_state_after_commit = Arc::try_unwrap(worker_executor_factory)
            .unwrap_or_else(|_| {
                panic!(
                    "To consume the block state, you must have only one strong reference to the \
                     worker executor factory. Consider dropping objects that hold a reference to \
                     it."
                )
            })
            .commit_chunk_and_recover_block_state(n_committed_txs);
        self.block_state.replace(block_state_after_commit);

        tx_execution_results
    }
}
