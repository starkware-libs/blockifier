use std::sync::Arc;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use itertools::FoldWhile::{Continue, Done};
use itertools::Itertools;
use starknet_api::core::ClassHash;
use thiserror::Error;

use crate::blockifier::config::TransactionExecutorConfig;
use crate::bouncer::{Bouncer, BouncerConfig};
use crate::context::BlockContext;
use crate::execution::call_info::CallInfo;
use crate::fee::actual_cost::TransactionReceipt;
use crate::state::cached_state::{CachedState, CommitmentStateDiff};
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
    pub state: CachedState<S>,
}

impl<S: StateReader> TransactionExecutor<S> {
    pub fn new(
        state: CachedState<S>,
        block_context: BlockContext,
        bouncer_config: BouncerConfig,
        config: TransactionExecutorConfig,
    ) -> Self {
        log::debug!("Initializing Transaction Executor...");
        // Note: the state might not be empty even at this point; it is the creator's
        // responsibility to tune the bouncer according to pre and post block process.
        let tx_executor =
            Self { block_context, bouncer: Bouncer::new(bouncer_config), config, state };
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
        let mut transactional_state = CachedState::create_transactional(&mut self.state);
        let validate = true;

        let tx_execution_result =
            tx.execute_raw(&mut transactional_state, &self.block_context, charge_fee, validate);
        match tx_execution_result {
            Ok(tx_execution_info) => {
                self.bouncer.try_update(
                    &mut transactional_state,
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

    pub fn execute_chunk(
        &mut self,
        _chunk: &[Transaction],
        _charge_fee: bool,
    ) -> Vec<TransactionExecutorResult<TransactionExecutionInfo>> {
        todo!()
    }

    pub fn execute_txs_sequentially(
        &mut self,
        txs: &[Transaction],
        charge_fee: bool,
    ) -> Vec<TransactionExecutorResult<TransactionExecutionInfo>> {
        let mut results_to_return = Vec::new();
        let results = txs.iter().map(|tx| self.execute(tx, charge_fee)).collect_vec();

        for result in results {
            match result {
                Ok(tx_execution_info) => results_to_return.push(Ok(tx_execution_info)),
                Err(TransactionExecutorError::BlockFull) => break,
                Err(error) => results_to_return.push(Err(error)),
            }
        }

        results_to_return
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
        self.state.increment_nonce(tx_info.sender_address())?;

        let limit_steps_by_resources = true;
        let validate_call_info = account_tx.validate_tx(
            &mut self.state,
            &mut execution_resources,
            tx_context.clone(),
            &mut remaining_gas,
            limit_steps_by_resources,
        )?;

        let tx_receipt = TransactionReceipt::from_account_tx(
            account_tx,
            &tx_context,
            &self.state.get_actual_state_changes()?,
            &execution_resources,
            validate_call_info.iter(),
            0,
        )?;

        Ok((validate_call_info, tx_receipt))
    }

    /// Returns the state diff and a list of contract class hash with the corresponding list of
    /// visited segment values.
    pub fn finalize(
        &mut self,
    ) -> TransactionExecutorResult<(CommitmentStateDiff, VisitedSegmentsMapping)> {
        // Get the visited segments of each contract class.
        // This is done by taking all the visited PCs of each contract, and compress them to one
        // representative for each visited segment.
        let visited_segments = self
            .state
            .visited_pcs
            .iter()
            .map(|(class_hash, class_visited_pcs)| -> TransactionExecutorResult<_> {
                let contract_class = self.state.get_compiled_contract_class(*class_hash)?;
                Ok((*class_hash, contract_class.get_visited_segments(class_visited_pcs)?))
            })
            .collect::<TransactionExecutorResult<_>>()?;

        log::debug!("Final block weights: {:?}.", self.bouncer.get_accumulated_weights());
        Ok((self.state.to_state_diff(), visited_segments))
    }
}
