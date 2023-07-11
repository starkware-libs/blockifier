use std::collections::HashSet;

use blockifier::block_context::BlockContext;
use blockifier::block_execution::pre_process_block;
use blockifier::state::cached_state::{CachedState, TransactionalState};
use blockifier::state::state_api::{State, StateReader};
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use ouroboros;
use papyrus_storage::db::RO;
use papyrus_storage::state::StateStorageReader;
use pyo3::prelude::*;
use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::core::ClassHash;

use crate::errors::{NativeBlockifierError, NativeBlockifierResult};
use crate::papyrus_state::{PapyrusReader, PapyrusStateReader};
use crate::py_block_executor::PyGeneralConfig;
use crate::py_state_diff::{PyBlockInfo, PyStateDiff};
use crate::py_transaction::py_tx;
use crate::py_transaction_execution_info::{PyTransactionExecutionInfo, PyVmExecutionResources};
use crate::py_utils::{py_enum_name, PyFelt};
use crate::storage::Storage;

// To access a field you must use `self.borrow_{field_name}()`.
// Alternately, you can borrow the whole object using `self.with[_mut]()`.
#[ouroboros::self_referencing]
pub struct TransactionExecutor {
    pub block_context: BlockContext,

    // Maintained for counting purposes.
    pub executed_class_hashes: HashSet<ClassHash>,

    // State-related fields.
    // Storage reader and transaction are kept merely for lifetime parameter referencing.
    pub storage_reader: papyrus_storage::StorageReader,
    #[borrows(storage_reader)]
    #[covariant]
    pub storage_tx: papyrus_storage::StorageTxn<'this, RO>,
    #[borrows(storage_tx)]
    #[covariant]
    pub state: CachedState<PapyrusReader<'this>>,
}

impl TransactionExecutor {
    pub fn create(
        storage: &Storage,
        general_config: &PyGeneralConfig,
        block_info: PyBlockInfo,
        max_recursion_depth: usize,
    ) -> NativeBlockifierResult<Self> {
        log::debug!("Initializing Transaction Executor...");
        // Assumption: storage is aligned.
        let reader = storage.reader().clone();

        let block_context = block_info.into_block_context(general_config, max_recursion_depth)?;
        let tx_executor = build_tx_executor(block_context, reader);
        log::debug!("Initialized Transaction Executor.");

        tx_executor
    }

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
        self.with_mut(|executor| {
            let mut transactional_state = CachedState::create_transactional(executor.state);
            let tx_execution_result = tx
                .execute_raw(&mut transactional_state, executor.block_context)
                .map_err(NativeBlockifierError::from);
            let (py_tx_execution_info, py_casm_hash_calculation_resources) =
                match tx_execution_result {
                    Ok(tx_execution_info) => {
                        tx_executed_class_hashes = tx_execution_info.get_executed_class_hashes();

                        let py_tx_execution_info = Python::with_gil(|py| {
                            // Allocate this instance on the Python heap.
                            // This is necessary in order to pass a reference to it to the callback
                            // (otherwise, if it were allocated on Rust's heap/stack, giving Python
                            // a reference to the objects will not
                            // work).
                            Py::new(py, PyTransactionExecutionInfo::from(tx_execution_info))
                                .expect("Should be able to allocate on Python heap")
                        });

                        let py_casm_hash_calculation_resources =
                            get_casm_hash_calculation_resources(
                                &mut transactional_state,
                                executor.executed_class_hashes,
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
                    executor.executed_class_hashes.extend(&tx_executed_class_hashes);
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
        })
    }

    pub fn finalize(&mut self) -> PyStateDiff {
        PyStateDiff::from(self.borrow_state().to_state_diff())
    }

    pub fn pre_process_block(
        &mut self,
        old_block_number_and_hash: Option<(u64, PyFelt)>,
    ) -> NativeBlockifierResult<()> {
        let old_block_number_and_hash = old_block_number_and_hash
            .map(|(block_number, block_hash)| (BlockNumber(block_number), BlockHash(block_hash.0)));

        self.with_mut(|executor| {
            pre_process_block(executor.state, old_block_number_and_hash);
        });

        Ok(())
    }
}

pub fn build_tx_executor(
    block_context: BlockContext,
    storage_reader: papyrus_storage::StorageReader,
) -> NativeBlockifierResult<TransactionExecutor> {
    // The following callbacks are required to capture the local lifetime parameter.
    fn storage_tx_builder(
        storage_reader: &papyrus_storage::StorageReader,
    ) -> NativeBlockifierResult<papyrus_storage::StorageTxn<'_, RO>> {
        Ok(storage_reader.begin_ro_txn()?)
    }

    fn state_builder<'a>(
        storage_tx: &'a papyrus_storage::StorageTxn<'a, RO>,
        block_number: BlockNumber,
    ) -> NativeBlockifierResult<CachedState<PapyrusReader<'a>>> {
        let state_reader = storage_tx.get_state_reader()?;
        let state_reader = PapyrusStateReader::new(state_reader, block_number);
        let papyrus_reader = PapyrusReader::new(storage_tx, state_reader);
        Ok(CachedState::new(papyrus_reader))
    }

    let executed_class_hashes = HashSet::<ClassHash>::new();
    let block_number = block_context.block_number;
    // The builder struct below is implicitly created by `ouroboros`.
    let py_tx_executor_builder = TransactionExecutorTryBuilder {
        block_context,
        executed_class_hashes,
        storage_reader,
        storage_tx_builder,
        state_builder: |storage_tx| state_builder(storage_tx, block_number),
    };
    py_tx_executor_builder.try_build()
}

fn unexpected_callback_error(error: &PyErr) -> bool {
    let error_string = error.to_string();
    !(error_string.contains("BatchFull") || error_string.contains("TransactionBiggerThanBatch"))
}

/// Returns the estimated VM resources for Casm hash calculation (done by the OS), of the newly
/// executed classes by the current transaction.
pub fn get_casm_hash_calculation_resources(
    state: &mut TransactionalState<'_, PapyrusReader<'_>>,
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
