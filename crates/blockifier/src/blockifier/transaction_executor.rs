use itertools::FoldWhile::{Continue, Done};
use itertools::Itertools;
use starknet_api::core::ClassHash;
use thiserror::Error;

use crate::blockifier::config::TransactionExecutorConfig;
use crate::bouncer::{Bouncer, BouncerWeights};
use crate::context::BlockContext;
use crate::state::cached_state::{CachedState, CommitmentStateDiff, TransactionalState};
use crate::state::errors::StateError;
use crate::state::state_api::StateReader;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::TransactionExecutionInfo;
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::ExecutableTransaction;

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
        let validate = true;
        let charge_fee = true;

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

    /// Executes the given transactions on the state maintained by the executor.
    /// Stops if and when there is no more room in the block, and returns the executed transactions'
    /// results.
    pub fn execute_txs(
        &mut self,
        txs: &[Transaction],
    ) -> Vec<TransactionExecutorResult<TransactionExecutionInfo>> {
        if !self.config.concurrency_config.enabled {
            self.execute_txs_sequentially(txs)
        } else {
            txs.chunks(self.config.concurrency_config.chunk_size)
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

    pub fn execute_chunk(
        &mut self,
        _chunk: &[Transaction],
    ) -> Vec<TransactionExecutorResult<TransactionExecutionInfo>> {
        todo!()
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
