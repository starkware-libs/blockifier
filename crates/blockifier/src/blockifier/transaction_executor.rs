#[cfg(feature = "concurrency")]
use std::collections::{HashMap, HashSet};
#[cfg(feature = "concurrency")]
use std::panic::{self, catch_unwind, AssertUnwindSafe};
#[cfg(feature = "concurrency")]
use std::sync::Arc;
#[cfg(feature = "concurrency")]
use std::sync::Mutex;

use itertools::FoldWhile::{Continue, Done};
use itertools::Itertools;
use starknet_api::core::ClassHash;
use thiserror::Error;

use crate::blockifier::config::TransactionExecutorConfig;
use crate::bouncer::{Bouncer, BouncerWeights};
#[cfg(feature = "concurrency")]
use crate::concurrency::worker_logic::WorkerExecutor;
use crate::context::BlockContext;
use crate::state::cached_state::{CachedState, CommitmentStateDiff, TransactionalState};
use crate::state::errors::StateError;
use crate::state::state_api::StateReader;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::TransactionExecutionInfo;
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::{ExecutableTransaction, ExecutionFlags};

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
    ) -> TransactionExecutorResult<TransactionExecutionInfo> {
        let mut transactional_state = TransactionalState::create_transactional(
            self.block_state.as_mut().expect(BLOCK_STATE_ACCESS_ERR),
        );
        // Executing a single transaction cannot be done in a concurrent mode.
        let execution_flags =
            ExecutionFlags { charge_fee: true, validate: true, concurrency_mode: false };
        let tx_execution_result =
            tx.execute_raw(&mut transactional_state, &self.block_context, execution_flags);
        match tx_execution_result {
            Ok(tx_execution_info) => {
                let tx_state_changes_keys =
                    transactional_state.get_actual_state_changes()?.into_keys();
                self.bouncer.try_update(
                    &transactional_state,
                    &tx_state_changes_keys,
                    &tx_execution_info.summarize(),
                    &tx_execution_info.transaction_receipt.resources,
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
    ) -> Vec<TransactionExecutorResult<TransactionExecutionInfo>> {
        let mut results = Vec::new();
        for tx in txs {
            match self.execute(tx) {
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
        _chunk: &[Transaction],
    ) -> Vec<TransactionExecutorResult<TransactionExecutionInfo>> {
        unimplemented!()
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
    ) -> Vec<TransactionExecutorResult<TransactionExecutionInfo>> {
        if !self.config.concurrency_config.enabled {
            log::debug!("Executing transactions sequentially.");
            self.execute_txs_sequentially(txs)
        } else {
            log::debug!("Executing transactions concurrently.");
            let chunk_size = self.config.concurrency_config.chunk_size;
            let n_workers = self.config.concurrency_config.n_workers;
            assert!(
                chunk_size > 0,
                "When running transactions concurrently the chunk size must be greater than 0. It \
                 equals {:?} ",
                chunk_size
            );
            assert!(
                n_workers > 0,
                "When running transactions concurrently the number of workers must be greater \
                 than 0. It equals {:?} ",
                n_workers
            );
            txs.chunks(chunk_size)
                .fold_while(Vec::new(), |mut results, chunk| {
                    let chunk_results = self.execute_chunk(chunk);
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
    ) -> Vec<TransactionExecutorResult<TransactionExecutionInfo>> {
        use crate::concurrency::utils::AbortIfPanic;

        let block_state = self.block_state.take().expect("The block state should be `Some`.");

        let worker_executor = Arc::new(WorkerExecutor::initialize(
            block_state,
            chunk,
            &self.block_context,
            Mutex::new(&mut self.bouncer),
        ));

        // No thread pool implementation is needed here since we already have our scheduler. The
        // initialized threads below will "busy wait" for new tasks using the `run` method until the
        // chunk execution is completed, and then they will be joined together in a for loop.
        // TODO(barak, 01/07/2024): Consider using tokio and spawn tasks that will be served by some
        // upper level tokio thread pool (Runtime in tokio terminology).
        std::thread::scope(|s| {
            for _ in 0..self.config.concurrency_config.n_workers {
                let worker_executor = Arc::clone(&worker_executor);
                s.spawn(move || {
                    // Making sure that the program will abort if a panic accured while halting the
                    // scheduler.
                    let abort_guard = AbortIfPanic;
                    // If a panic is not handled or the handling logic itself panics, then we abort
                    // the program.
                    if let Err(err) = catch_unwind(AssertUnwindSafe(|| {
                        worker_executor.run();
                    })) {
                        // If the program panics here, the abort guard will exit the program.
                        // In this case, no panic message will be logged. Add the cargo flag
                        // --nocapture to log the panic message.

                        worker_executor.scheduler.halt();
                        abort_guard.release();
                        panic::resume_unwind(err);
                    }

                    abort_guard.release();
                });
            }
        });

        let n_committed_txs = worker_executor.scheduler.get_n_committed_txs();
        let mut tx_execution_results = Vec::new();
        let mut visited_pcs: HashMap<ClassHash, HashSet<usize>> = HashMap::new();
        for execution_output in worker_executor.execution_outputs.iter() {
            if tx_execution_results.len() >= n_committed_txs {
                break;
            }
            let locked_execution_output = execution_output
                .lock()
                .expect("Failed to lock execution output.")
                .take()
                .expect("Output must be ready.");
            tx_execution_results
                .push(locked_execution_output.result.map_err(TransactionExecutorError::from));
            for (class_hash, class_visited_pcs) in locked_execution_output.visited_pcs {
                visited_pcs.entry(class_hash).or_default().extend(class_visited_pcs);
            }
        }

        let block_state_after_commit = Arc::try_unwrap(worker_executor)
            .unwrap_or_else(|_| {
                panic!(
                    "To consume the block state, you must have only one strong reference to the \
                     worker executor factory. Consider dropping objects that hold a reference to \
                     it."
                )
            })
            .commit_chunk_and_recover_block_state(n_committed_txs, visited_pcs);
        self.block_state.replace(block_state_after_commit);

        tx_execution_results
    }
}
