use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::vec::IntoIter;

use blockifier::context::BlockContext;
use blockifier::execution::bouncer::BouncerInfo;
use blockifier::execution::call_info::{CallInfo, MessageL1CostInfo};
use blockifier::fee::actual_cost::ActualCost;
use blockifier::fee::gas_usage::get_onchain_data_segment_length;
use blockifier::state::cached_state::{
    CachedState, CommitmentStateDiff, StagedTransactionalState, StateChangesKeys, StorageEntry,
    TransactionalState,
};
use blockifier::state::state_api::{State, StateReader};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::objects::TransactionExecutionInfo;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::{ExecutableTransaction, ValidatableTransaction};
use cairo_vm::vm::runners::builtin_runner::HASH_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use starknet_api::core::ClassHash;

use crate::errors::{NativeBlockifierError, NativeBlockifierResult};

pub(crate) type RawTransactionExecutionInfo = Vec<u8>;

// TODO(Gilad): make this hold TransactionContext instead of BlockContext.
pub struct TransactionExecutor<S: StateReader> {
    pub block_context: BlockContext,

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
    pub fn new(state: CachedState<S>, block_context: BlockContext) -> NativeBlockifierResult<Self> {
        log::debug!("Initializing Transaction Executor...");
        let tx_executor = Self {
            block_context,
            executed_class_hashes: HashSet::<ClassHash>::new(),
            visited_storage_entries: HashSet::<StorageEntry>::new(),
            // Note: the state might not be empty even at this point; it is the creator's
            // responsibility to tune the bouncer according to pre and post block process.
            state_changes_keys: StateChangesKeys::default(),
            state,
            staged_for_commit_state: None,
        };
        log::debug!("Initialized Transaction Executor.");

        Ok(tx_executor)
    }

    /// Executes the given transaction on the state maintained by the executor.
    /// Returns the execution trace, together with the compiled class hashes of executed classes
    /// (used for counting purposes).
    pub fn execute(
        &mut self,
        tx: Transaction,
        charge_fee: bool,
    ) -> NativeBlockifierResult<(TransactionExecutionInfo, BouncerInfo)> {
        let l1_handler_payload_size: Option<usize> =
            if let Transaction::L1HandlerTransaction(l1_handler_tx) = &tx {
                Some(l1_handler_tx.payload_size())
            } else {
                None
            };
        let mut tx_executed_class_hashes = HashSet::<ClassHash>::new();
        let mut tx_visited_storage_entries = HashSet::<StorageEntry>::new();
        let mut transactional_state = CachedState::create_transactional(&mut self.state);
        let validate = true;

        let tx_execution_result = tx
            .execute_raw(&mut transactional_state, &self.block_context, charge_fee, validate)
            .map_err(NativeBlockifierError::from);
        match tx_execution_result {
            Ok(tx_execution_info) => {
                // Prepare bouncer info; the countings here should be linear in the transactional
                // state changes and execution info rather than the cumulative state attributes.

                // TODO(Elin, 01/06/2024): consider traversing the calls to collect data once.
                // TODO(Elin, 01/06/2024): consider moving Bouncer logic to a function.
                tx_executed_class_hashes.extend(tx_execution_info.get_executed_class_hashes());
                tx_visited_storage_entries.extend(tx_execution_info.get_visited_storage_entries());
                let n_events = tx_execution_info.get_number_of_events();

                // Count message to L1 resources.
                let call_infos: IntoIter<&CallInfo> =
                    [&tx_execution_info.validate_call_info, &tx_execution_info.execute_call_info]
                        .iter()
                        .filter_map(|&call_info| call_info.as_ref())
                        .collect::<Vec<&CallInfo>>()
                        .into_iter();
                let MessageL1CostInfo { l2_to_l1_payload_lengths: _, message_segment_length } =
                    MessageL1CostInfo::calculate(call_infos, l1_handler_payload_size)?;

                // Count additional OS resources.
                let mut additional_os_resources = get_casm_hash_calculation_resources(
                    &mut transactional_state,
                    &self.executed_class_hashes,
                    &tx_executed_class_hashes,
                )?;
                additional_os_resources += &get_particia_update_resources(
                    &self.visited_storage_entries,
                    &tx_visited_storage_entries,
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
                    get_onchain_data_segment_length(tx_unique_state_changes_keys.count());

                // Finalize counting logic.
                let actual_resources = &tx_execution_info.actual_resources;
                let bouncer_info = BouncerInfo::calculate(
                    actual_resources,
                    additional_os_resources,
                    message_segment_length,
                    state_diff_size,
                    n_events,
                )?;
                self.staged_for_commit_state = Some(transactional_state.stage(
                    tx_executed_class_hashes,
                    tx_visited_storage_entries,
                    tx_unique_state_changes_keys,
                ));

                Ok((tx_execution_info, bouncer_info))
            }
            Err(error) => {
                transactional_state.abort();
                Err(error)
            }
        }
    }

    pub fn validate(
        &mut self,
        account_tx: &AccountTransaction,
        mut remaining_gas: u64,
    ) -> NativeBlockifierResult<(Option<CallInfo>, ActualCost)> {
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
        let mut tx_n_emitted_events = 0;
        let validate_call_info = account_tx.validate_tx(
            &mut self.state,
            &mut execution_resources,
            tx_context.clone(),
            &mut remaining_gas,
            limit_steps_by_resources,
            &mut tx_n_emitted_events,
        )?;

        let actual_cost = account_tx
            .to_actual_cost_builder(tx_context)
            .with_validate_call_info(&validate_call_info)
            .try_add_state_changes(&mut self.state)?
            .build(&execution_resources)?;

        Ok((validate_call_info, actual_cost))
    }

    /// Returns the state diff and a list of contract class hash with the corresponding list of
    /// visited PC values.
    pub fn finalize(
        &mut self,
        is_pending_block: bool,
    ) -> (CommitmentStateDiff, Vec<(ClassHash, Vec<usize>)>) {
        // Do not cache classes that were declared during a pending block.
        // They will be redeclared, and should not be cached since the content of this block is
        // transient.
        if !is_pending_block {
            self.state.move_classes_to_global_cache();
        }

        // Extract visited PCs from block_context, and convert it to a python-friendly type.
        let visited_pcs = self
            .state
            .visited_pcs
            .iter()
            .map(|(class_hash, class_visited_pcs)| {
                let mut class_visited_pcs_vec: Vec<_> = class_visited_pcs.iter().cloned().collect();
                class_visited_pcs_vec.sort();
                (*class_hash, class_visited_pcs_vec)
            })
            .collect();

        (self.state.to_state_diff(), visited_pcs)
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
) -> NativeBlockifierResult<ExecutionResources> {
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
) -> NativeBlockifierResult<ExecutionResources> {
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
