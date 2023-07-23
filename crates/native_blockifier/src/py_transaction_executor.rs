use std::collections::HashSet;

use blockifier::block_context::BlockContext;
use blockifier::block_execution::pre_process_block;
use blockifier::state::cached_state::{CachedState, TransactionalState};
use blockifier::state::state_api::{State, StateReader};
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use pyo3::prelude::*;
use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::core::ClassHash;

use crate::errors::{NativeBlockifierError, NativeBlockifierResult};
use crate::papyrus_state::PapyrusReader;
use crate::py_block_executor::PyGeneralConfig;
use crate::py_state_diff::{PyBlockInfo, PyStateDiff};
use crate::py_transaction::py_tx;
use crate::py_transaction_execution_info::{PyTransactionExecutionInfo, PyVmExecutionResources};
use crate::py_utils::{py_enum_name, PyFelt};
use crate::storage::Storage;

/// Wraps the transaction executor in an optional, to allow an explicit deallocation of it.
/// The explicit deallocation is needed since PyO3 can't track lifetimes within Python.

pub struct TransactionExecutor {
    pub block_context: BlockContext,

    // Maintained for counting purposes.
    pub executed_class_hashes: HashSet<ClassHash>,

    // State-related fields.
    pub state: CachedState<PapyrusReader>,
}

impl TransactionExecutor {
    pub fn new(
        papyrus_storage: &Storage,
        general_config: &PyGeneralConfig,
        block_info: PyBlockInfo,
        max_recursion_depth: usize,
    ) -> NativeBlockifierResult<Self> {
        log::debug!("Initializing Transaction Executor...");
        // Assumption: storage is aligned.
        let reader = papyrus_storage.reader().clone();

        let block_context = general_config.into_block_context(block_info, max_recursion_depth)?;
        let state = CachedState::new(PapyrusReader::new(reader, block_context.block_number));
        let executed_class_hashes = HashSet::<ClassHash>::new();
        log::debug!("Initialized Transaction Executor.");
        Ok(Self { block_context, executed_class_hashes, state })
    }

    /// Executes the given transaction on the state maintained by the executor.
    /// Returns the execution trace, together with the compiled class hashes of executed classes
    /// (used for counting purposes).
    pub fn execute(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
        // This is functools.partial(bouncer.add, tw_written=tx_written).
        enough_room_for_tx: &PyAny,
    ) -> NativeBlockifierResult<(Py<PyTransactionExecutionInfo>, PyVmExecutionResources)> {
        let tx_type: String = py_enum_name(tx, "tx_type")?;
        let tx: Transaction = py_tx(&tx_type, tx, raw_contract_class)?;

        let mut tx_executed_class_hashes = HashSet::<ClassHash>::new();
        let mut transactional_state = CachedState::create_transactional(&mut self.state);
        let tx_execution_result = tx
            .execute_raw(&mut transactional_state, &self.block_context, true)
            .map_err(NativeBlockifierError::from);
        let (py_tx_execution_info, py_casm_hash_calculation_resources) = match tx_execution_result {
            Ok(tx_execution_info) => {
                tx_executed_class_hashes.extend(tx_execution_info.get_executed_class_hashes());

                let py_tx_execution_info = Python::with_gil(|py| {
                    // Allocate this instance on the Python heap.
                    // This is necessary in order to pass a reference to it to the callback
                    // (otherwise, if it were allocated on Rust's heap/stack, giving Python
                    // a reference to the objects will not
                    // work).
                    Py::new(py, PyTransactionExecutionInfo::from(tx_execution_info))
                        .expect("Should be able to allocate on Python heap")
                });

                let py_casm_hash_calculation_resources = get_casm_hash_calculation_resources(
                    &mut transactional_state,
                    &self.executed_class_hashes,
                    &tx_executed_class_hashes,
                )?;

                (py_tx_execution_info, py_casm_hash_calculation_resources)
            }
            Err(error) => {
                transactional_state.abort();
                return Err(error);
            }
        };

        let has_enough_room_for_tx = Python::with_gil(|py| {
            // Can be done because `py_tx_execution_info` is a `Py<PyTransactionExecutionInfo>`,
            // hence is allocated on the Python heap.
            let args =
                (py_tx_execution_info.borrow(py), py_casm_hash_calculation_resources.clone());
            enough_room_for_tx.call1(args) // Callback to Python code.
        });

        match has_enough_room_for_tx {
            Ok(_) => {
                transactional_state.commit();
                self.executed_class_hashes.extend(&tx_executed_class_hashes);
                Ok((py_tx_execution_info, py_casm_hash_calculation_resources))
            }
            // Unexpected error, abort and let caller know.
            Err(error) if unexpected_callback_error(&error) => {
                transactional_state.abort();
                Err(error.into())
            }
            // Not enough room in batch, abort and let caller verify on its own.
            Err(_not_enough_weight_error) => {
                transactional_state.abort();
                Ok((py_tx_execution_info, py_casm_hash_calculation_resources))
            }
        }
    }

    /// Returns the state diff resulting in executing transactions.
    pub fn finalize(&mut self) -> PyStateDiff {
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
}

fn unexpected_callback_error(error: &PyErr) -> bool {
    let error_string = error.to_string();
    !(error_string.contains("BatchFull") || error_string.contains("TransactionBiggerThanBatch"))
}

/// Returns the estimated VM resources for Casm hash calculation (done by the OS), of the newly
/// executed classes by the current transaction.
pub fn get_casm_hash_calculation_resources(
    state: &mut TransactionalState<'_, PapyrusReader>,
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
