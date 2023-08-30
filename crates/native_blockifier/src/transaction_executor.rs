use std::collections::HashSet;

use blockifier::block_context::BlockContext;
use blockifier::block_execution::pre_process_block;
use blockifier::state::cached_state::{
    CachedState, GlobalContractCache, StagedTransactionalState, TransactionalState,
};
use blockifier::state::state_api::{State, StateReader};
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use pyo3::prelude::*;
use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::core::ClassHash;

use crate::errors::{NativeBlockifierError, NativeBlockifierResult};
use crate::py_block_executor::{into_block_context, PyGeneralConfig};
use crate::py_state_diff::{PyBlockInfo, PyStateDiff};
use crate::py_transaction::py_tx;
use crate::py_transaction_execution_info::{PyTransactionExecutionInfo, PyVmExecutionResources};
use crate::py_utils::{py_enum_name, PyFelt};

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
    ) -> NativeBlockifierResult<(PyTransactionExecutionInfo, PyVmExecutionResources)> {
        let tx_type: String = py_enum_name(tx, "tx_type")?;
        let tx: Transaction = py_tx(&tx_type, tx, raw_contract_class)?;

        let mut tx_executed_class_hashes = HashSet::<ClassHash>::new();
        let mut transactional_state = CachedState::create_transactional(&mut self.state);
        let validate = true;
        let tx_execution_result = tx
            .execute_raw(&mut transactional_state, &self.block_context, charge_fee, validate)
            .map_err(NativeBlockifierError::from);
        match tx_execution_result {
            Ok(tx_execution_info) => {
                tx_executed_class_hashes.extend(tx_execution_info.get_executed_class_hashes());

                let py_tx_execution_info = PyTransactionExecutionInfo::from(tx_execution_info);
                let py_casm_hash_calculation_resources = get_casm_hash_calculation_resources(
                    &mut transactional_state,
                    &self.executed_class_hashes,
                    &tx_executed_class_hashes,
                )?;

                self.staged_for_commit_state =
                    Some(transactional_state.stage(tx_executed_class_hashes));
                Ok((py_tx_execution_info, py_casm_hash_calculation_resources))
            }
            Err(error) => {
                transactional_state.abort();
                Err(error)
            }
        }
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
