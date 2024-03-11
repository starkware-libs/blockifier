use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cairo_vm::vm::runners::builtin_runner::HASH_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use starknet_api::core::ClassHash;
use thiserror::Error;

use crate::blockifier::bouncer::BouncerInfo;
use crate::bouncer::{Bouncer, BouncerConfig, HashMapWrapper};
use crate::context::BlockContext;
use crate::execution::call_info::CallInfo;
use crate::fee::actual_cost::TransactionReceipt;
use crate::fee::gas_usage::get_onchain_data_segment_length;
use crate::state::cached_state::{
    CachedState, CommitmentStateDiff, StagedTransactionalState, StateChangesKeys, StorageEntry,
    TransactionalState,
};
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

    // Maintained for counting purposes.
    pub executed_class_hashes: HashSet<ClassHash>,
    pub visited_storage_entries: HashSet<StorageEntry>,
    // This member should be consistent with the state's modified keys.
    state_changes_keys: StateChangesKeys,

    // State-related fields.
    pub state: CachedState<S>,

    // Transactional state, awaiting commit/abort call.
    // Is `Some` only after transaction has finished executing, and before commit/revert have been
    // called. `None` while a transaction is being executed and in between transactions.
    pub staged_for_commit_state: Option<StagedTransactionalState>,
}

impl<S: StateReader> TransactionExecutor<S> {
    pub fn new(
        state: CachedState<S>,
        block_context: BlockContext,
        bouncer_config: BouncerConfig,
    ) -> Self {
        log::debug!("Initializing Transaction Executor...");
        println!("yael TransactionExecutor::new  bouncer_config: {:?}", bouncer_config);
        let tx_executor = Self {
            block_context,
            bouncer: Bouncer::new(bouncer_config),
            executed_class_hashes: HashSet::<ClassHash>::new(),
            visited_storage_entries: HashSet::<StorageEntry>::new(),
            // Note: the state might not be empty even at this point; it is the creator's
            // responsibility to tune the bouncer according to pre and post block process.
            state_changes_keys: StateChangesKeys::default(),
            state,
            staged_for_commit_state: None,
        };
        println!(
            "yael TransactionExecutor::new  bouncer_config: {:?}",
            tx_executor.bouncer.bouncer_config
        );

        log::debug!("Initialized Transaction Executor.");

        tx_executor
    }

    /// Executes the given transaction on the state maintained by the executor.
    /// Returns the execution trace and the resources consumed by the transaction (required for the
    /// bouncer).
    pub fn execute(
        &mut self,
        tx: Transaction,
        charge_fee: bool,
    ) -> TransactionExecutorResult<(
        TransactionExecutionInfo,
        BouncerInfo,
        HashMap<String, usize>,
        i32,
    )> {
        println!(
            "yael TransactionExecutor::execute , block number: {}, bouncer_config: {:?}",
            self.block_context.block_info.block_number, self.bouncer.bouncer_config
        );
        let mut transactional_state = CachedState::create_transactional(&mut self.state);
        let validate = true;

        let tx_execution_result =
            tx.execute_raw(&mut transactional_state, &self.block_context, charge_fee, validate);
        match tx_execution_result {
            Ok(tx_execution_info) => {
                // New Bouncer code.
                // TODO(Yael): Return the error and remove the old bouncer code in the following
                // PRs.
                println!(
                    "yael TransactionExecutor::execute , tx_execution_info: {:?}",
                    tx_execution_info.actual_resources
                );
                let prev_bouncer = self.bouncer.clone();
                let tx_execution_summary = tx_execution_info.summarize();
                let res = self.bouncer.try_update(
                    &mut transactional_state,
                    &tx_execution_summary,
                    &tx_execution_info.actual_resources,
                );
                println!("yael Bouncer res: {:?}", res);
                // Prepare bouncer info; the countings here should be linear in the transactional
                // state changes and execution info rather than the cumulative state attributes.

                // TODO(Elin, 01/06/2024): consider moving Bouncer logic to a function.
                let tx_execution_summary = tx_execution_info.summarize();

                // Count additional OS resources.
                // TODO(Nimrod, 1/5/2024): Move this computation to TransactionResources.
                let mut additional_os_resources = get_casm_hash_calculation_resources(
                    &mut transactional_state,
                    &self.executed_class_hashes,
                    &tx_execution_summary.executed_class_hashes,
                )?;
                additional_os_resources += &get_particia_update_resources(
                    &self.visited_storage_entries,
                    &tx_execution_summary.visited_storage_entries,
                )?;

                // Count residual state diff size (w.r.t. the OS output encoding).
                let tx_state_changes_keys =
                    transactional_state.get_actual_state_changes()?.into_keys();
                let tx_unique_state_changes_keys =
                    tx_state_changes_keys.difference(&self.state_changes_keys);
                // Note: block-constant felts are not counted here. so the bouncer needs to
                // tune the size limit accordingly. E.g., the felt that encodes the number of
                // modified contracts in a block.
                let state_diff_size =
                    get_onchain_data_segment_length(&tx_unique_state_changes_keys.count());

                // Finalize counting logic.
                let bouncer_info = tx_execution_info.actual_resources.to_bouncer_info(
                    &self.block_context.versioned_constants,
                    self.block_context.block_info.use_kzg_da,
                    additional_os_resources,
                    state_diff_size,
                )?;
                self.staged_for_commit_state = Some(transactional_state.stage(
                    tx_execution_summary.executed_class_hashes.clone(),
                    tx_execution_summary.visited_storage_entries.clone(),
                    tx_unique_state_changes_keys.clone(),
                ));

                // Code for testing the new bouncer.
                let mut result = 0;
                if let Ok(()) = res {
                    Bouncer::compare_bouncer_results(
                        &prev_bouncer,
                        &bouncer_info,
                        &self.bouncer,
                        &tx_execution_summary.executed_class_hashes,
                        &tx_execution_summary.visited_storage_entries,
                        &tx_unique_state_changes_keys,
                    );
                } else if matches!(
                    res.as_ref().unwrap_err(),
                    TransactionExecutorError::TransactionExecutionError(
                        TransactionExecutionError::BlockFull
                    )
                ) {
                    result = 1;
                } else if matches!(
                    res.as_ref().unwrap_err(),
                    TransactionExecutorError::TransactionExecutionError(
                        TransactionExecutionError::TransactionTooLarge
                    )
                ) {
                    result = 2;
                } else {
                    panic!("Unexpected error: {:?}", res.unwrap_err());
                }

                let accumulated_weights: HashMapWrapper =
                    (*self.bouncer.accumulated_weights()).into();

                Ok((tx_execution_info, bouncer_info, accumulated_weights, result))
            }
            Err(error) => {
                transactional_state.abort();
                Err(TransactionExecutorError::TransactionExecutionError(error))
            }
        }
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
        is_pending_block: bool,
    ) -> TransactionExecutorResult<(CommitmentStateDiff, VisitedSegmentsMapping)> {
        // Do not cache classes that were declared during a pending block.
        // They will be redeclared, and should not be cached since the content of this block is
        // transient.
        if !is_pending_block {
            self.state.move_classes_to_global_cache();
        }

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

        Ok((self.state.to_state_diff(), visited_segments))
    }

    pub fn commit(&mut self) {
        let Some(finalized_transactional_state) = self.staged_for_commit_state.take() else {
            panic!("commit called without a transactional state")
        };

        let child_cache = finalized_transactional_state.cache;
        self.state.update_cache(child_cache);
        self.state.update_contract_class_caches(
            finalized_transactional_state.class_hash_to_class,
            finalized_transactional_state.global_class_hash_to_class,
        );
        self.state.update_visited_pcs_cache(&finalized_transactional_state.visited_pcs);

        self.executed_class_hashes.extend(&finalized_transactional_state.tx_executed_class_hashes);
        self.visited_storage_entries
            .extend(&finalized_transactional_state.tx_visited_storage_entries);

        // Note: cancelling writes (0 -> 1 -> 0) will not be removed,
        // but it's fine since fee was charged for them.
        self.state_changes_keys.extend(&finalized_transactional_state.tx_unique_state_changes_keys);

        self.staged_for_commit_state = None
    }

    pub fn abort(&mut self) {
        self.staged_for_commit_state = None
    }
}

/// Returns the estimated VM resources for Casm hash calculation (done by the OS), of the newly
/// executed classes by the current transaction.
pub fn get_casm_hash_calculation_resources<S: StateReader>(
    state: &mut TransactionalState<'_, S>,
    block_executed_class_hashes: &HashSet<ClassHash>,
    tx_executed_class_hashes: &HashSet<ClassHash>,
) -> TransactionExecutorResult<ExecutionResources> {
    let newly_executed_class_hashes: HashSet<&ClassHash> =
        tx_executed_class_hashes.difference(block_executed_class_hashes).collect();

    let mut casm_hash_computation_resources = ExecutionResources::default();

    for class_hash in newly_executed_class_hashes {
        let class = state.get_compiled_contract_class(*class_hash)?;
        casm_hash_computation_resources += &class.estimate_casm_hash_computation_resources();
    }

    Ok(casm_hash_computation_resources)
}

/// Returns the estimated VM resources for Patricia tree updates, or hash invocations
/// (done by the OS), required by the execution of the current transaction.
// For each tree: n_visited_leaves * log(n_initialized_leaves)
// as the height of a Patricia tree with N uniformly distributed leaves is ~log(N),
// and number of visited leaves includes reads and writes.
pub fn get_particia_update_resources(
    block_visited_storage_entries: &HashSet<StorageEntry>,
    tx_visited_storage_entries: &HashSet<StorageEntry>,
) -> TransactionExecutorResult<ExecutionResources> {
    let newly_visited_storage_entries: HashSet<&StorageEntry> =
        tx_visited_storage_entries.difference(block_visited_storage_entries).collect();
    let n_newly_visited_leaves = newly_visited_storage_entries.len();

    const TREE_HEIGHT_UPPER_BOUND: usize = 24;
    let n_updates = n_newly_visited_leaves * TREE_HEIGHT_UPPER_BOUND;

    let patricia_update_resources = ExecutionResources {
        // TODO(Yoni, 1/5/2024): re-estimate this.
        n_steps: 32 * n_updates,
        // For each Patricia update there are two hash calculations.
        builtin_instance_counter: HashMap::from([(HASH_BUILTIN_NAME.to_string(), 2 * n_updates)]),
        n_memory_holes: 0,
    };

    Ok(patricia_update_resources)
}
