use std::collections::HashSet;

use blockifier::block_context::BlockContext;
use blockifier::block_execution::pre_process_block;
use blockifier::execution::call_info::CallInfo;
use blockifier::execution::entry_point::ExecutionResources;
use blockifier::fee::actual_cost::ActualCost;
use blockifier::fee::gas_usage::calculate_message_segment_size;
use blockifier::state::cached_state::{
    CachedState, GlobalContractCache, StagedTransactionalState, TransactionalState,
};
use blockifier::state::state_api::{State, StateReader};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::{ExecutableTransaction, ValidatableTransaction};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use pyo3::prelude::*;
use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::core::ClassHash;

use crate::errors::{NativeBlockifierError, NativeBlockifierResult};
use crate::py_block_executor::{into_block_context, PyGeneralConfig};
use crate::py_state_diff::{PyBlockInfo, PyStateDiff};
use crate::py_transaction::py_tx;
use crate::py_transaction_execution_info::{
    PyBouncerInfo, PyTransactionExecutionInfo, PyVmExecutionResources,
};
use crate::py_utils::PyFelt;

pub struct TransactionExecutor<S: StateReader> {
    pub block_context: BlockContext,

    // Maintained for counting purposes.
    pub executed_class_hashes: HashSet<ClassHash>,

    // State-related fields.
    pub state: CachedState<S>,

    // Transactional state, awaiting commit/abort call.
    // Is `Some` only after transaction has finished executing, and before commit/revert have been
    // called. `None` while a transaction is being executed and in between transactions.
    pub staged_for_commit_state: Option<StagedTransactionalState>,
}

impl<S: StateReader> TransactionExecutor<S> {
    pub fn new(
        state_reader: S,
        general_config: &PyGeneralConfig,
        block_info: PyBlockInfo,
        max_recursion_depth: usize,
        global_contract_cache: GlobalContractCache,
    ) -> NativeBlockifierResult<Self> {
        log::debug!("Initializing Transaction Executor...");

        let block_context = into_block_context(general_config, block_info, max_recursion_depth)?;
        let state = CachedState::new(state_reader, global_contract_cache);
        let executed_class_hashes = HashSet::<ClassHash>::new();
        log::debug!("Initialized Transaction Executor.");
        Ok(Self { block_context, executed_class_hashes, state, staged_for_commit_state: None })
    }

    /// Executes the given transaction on the state maintained by the executor.
    /// Returns the execution trace, together with the compiled class hashes of executed classes
    /// (used for counting purposes).
    pub fn execute(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
        charge_fee: bool,
    ) -> NativeBlockifierResult<(PyTransactionExecutionInfo, PyBouncerInfo)> {
        let tx: Transaction = py_tx(tx, raw_contract_class)?;
        let l1_handler_payload_size: Option<usize> =
            if let Transaction::L1HandlerTransaction(l1_handler_tx) = &tx {
                l1_handler_tx.get_payload_size()
            } else {
                Some(0)
            };
        let mut tx_executed_class_hashes = HashSet::<ClassHash>::new();
        let mut transactional_state = CachedState::create_transactional(&mut self.state);
        let validate = true;
        let tx_execution_result = tx
            .execute_raw(&mut transactional_state, &self.block_context, charge_fee, validate)
            .map_err(NativeBlockifierError::from);
        match tx_execution_result {
            Ok(tx_execution_info) => {
                tx_executed_class_hashes.extend(tx_execution_info.get_executed_class_hashes());
                let message_segment_size = calculate_message_segment_size(
                    &tx_execution_info.validate_call_info,
                    &tx_execution_info.execute_call_info,
                    l1_handler_payload_size,
                )?;
                let py_casm_hash_calculation_resources = get_casm_hash_calculation_resources(
                    &mut transactional_state,
                    &self.executed_class_hashes,
                    &tx_executed_class_hashes,
                )?;
                let py_bouncer_info = PyBouncerInfo {
                    messages_size: message_segment_size,
                    casm_hash_calculation_resources: py_casm_hash_calculation_resources,
                };
                self.staged_for_commit_state =
                    Some(transactional_state.stage(tx_executed_class_hashes));
                let py_tx_execution_info = PyTransactionExecutionInfo::from(tx_execution_info);

                Ok((py_tx_execution_info, py_bouncer_info))
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
        let account_tx_context = account_tx.get_account_tx_context();

        // TODO(Amos, 01/12/2023): Delete this once deprecated txs call
        // PyValidator.perform_validations().
        // For fee charging purposes, the nonce-increment cost is taken into consideration when
        // calculating the fees for validation.
        // Note: This assumes that the state is reset between calls to validate.
        self.state.increment_nonce(account_tx_context.sender_address())?;

        let validate_call_info = account_tx.validate_tx(
            &mut self.state,
            &mut execution_resources,
            &account_tx_context,
            &mut remaining_gas,
            &self.block_context,
            true,
        )?;

        let actual_cost = account_tx
            .into_actual_cost_builder(&self.block_context)
            .with_validate_call_info(&validate_call_info)
            .try_add_state_changes(&mut self.state)?
            .build(&execution_resources)?;

        Ok((validate_call_info, actual_cost))
    }

    /// Returns the state diff resulting in executing transactions.
    pub fn finalize(&mut self, is_pending_block: bool) -> PyStateDiff {
        // Do not cache classes that were declared during a pending block.
        // They will be redeclared, and should not be cached since the content of this block is
        // transient.
        if !is_pending_block {
            self.state.move_classes_to_global_cache();
        }

        PyStateDiff::from(self.state.to_state_diff())
    }

    // Block pre-processing; see `block_execution::pre_process_block` documentation.
    pub fn pre_process_block(
        &mut self,
        old_block_number_and_hash: Option<(u64, PyFelt)>,
    ) -> NativeBlockifierResult<()> {
        let old_block_number_and_hash = old_block_number_and_hash
            .map(|(block_number, block_hash)| (BlockNumber(block_number), BlockHash(block_hash.0)));

        pre_process_block(&mut self.state, old_block_number_and_hash);

        Ok(())
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

        self.executed_class_hashes.extend(&finalized_transactional_state.tx_executed_class_hashes);

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
    executed_class_hashes: &HashSet<ClassHash>,
    tx_executed_class_hashes: &HashSet<ClassHash>,
) -> NativeBlockifierResult<PyVmExecutionResources> {
    let newly_executed_class_hashes: HashSet<&ClassHash> =
        tx_executed_class_hashes.difference(executed_class_hashes).collect();

    let mut casm_hash_computation_resources = VmExecutionResources::default();

    for class_hash in newly_executed_class_hashes {
        let class = state.get_compiled_contract_class(class_hash)?;
        casm_hash_computation_resources += &class.estimate_casm_hash_computation_resources();
    }

    Ok(PyVmExecutionResources::from(casm_hash_computation_resources))
}
