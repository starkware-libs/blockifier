use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use blockifier::block_context::BlockContext;
use blockifier::block_execution::pre_process_block;
use blockifier::state::cached_state::{CachedState, TransactionalState};
use blockifier::state::state_api::{State, StateReader};
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use pyo3::prelude::*;
use starknet_api::block::{BlockHash, BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ClassHash, ContractAddress};

use crate::errors::{NativeBlockifierError, NativeBlockifierResult};
use crate::papyrus_state::PapyrusReader;
use crate::py_state_diff::PyStateDiff;
use crate::py_transaction::py_tx;
use crate::py_transaction_execution_info::{PyTransactionExecutionInfo, PyVmExecutionResources};
use crate::py_utils::{int_to_chain_id, py_attr, py_enum_name, PyFelt};
use crate::storage::Storage;

/// Wraps the transaction executor in an optional, to allow an explicit deallocation of it.
/// The explicit deallocation is needed since PyO3 can't track lifetimes within Python.
#[pyclass]
pub struct PyTransactionExecutor {
    pub executor: Option<TransactionExecutor>,
}

#[pymethods]
impl PyTransactionExecutor {
    #[new]
    #[args(papyrus_storage, general_config, block_info, max_recursion_depth)]
    pub fn create(
        papyrus_storage: &Storage,
        general_config: PyGeneralConfig,
        block_info: &PyAny,
        max_recursion_depth: usize,
    ) -> NativeBlockifierResult<Self> {
        log::debug!("Initializing Transaction Executor...");
        let executor = TransactionExecutor::new(
            papyrus_storage,
            general_config,
            block_info,
            max_recursion_depth,
        )?;
        log::debug!("Initialized Transaction Executor.");

        Ok(Self { executor: Some(executor) })
    }

    #[args(tx, raw_contract_class, enough_room_for_tx)]
    pub fn execute(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
        // This is functools.partial(bouncer.add, tw_written=tx_written).
        enough_room_for_tx: &PyAny,
    ) -> NativeBlockifierResult<(Py<PyTransactionExecutionInfo>, PyVmExecutionResources)> {
        self.executor().execute(tx, raw_contract_class, enough_room_for_tx)
    }

    pub fn finalize(&mut self) -> PyStateDiff {
        log::debug!("Finalizing execution...");
        let finalized_state = self.executor().finalize();
        log::debug!("Finalized execution.");

        finalized_state
    }

    pub fn close(&mut self) {
        self.executor = None;
    }

    #[args(old_block_number_and_hash)]
    pub fn pre_process_block(
        &mut self,
        old_block_number_and_hash: Option<(u64, PyFelt)>,
    ) -> NativeBlockifierResult<()> {
        self.executor().pre_process_block(old_block_number_and_hash)
    }
}

impl PyTransactionExecutor {
    fn executor(&mut self) -> &mut TransactionExecutor {
        self.executor.as_mut().expect("Transaction executor should be initialized.")
    }
}

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
        general_config: PyGeneralConfig,
        block_info: &PyAny,
        max_recursion_depth: usize,
    ) -> NativeBlockifierResult<Self> {
        // Assumption: storage is aligned.
        let reader = papyrus_storage.reader().clone();

        let block_context = py_block_context(general_config, block_info, max_recursion_depth)?;
        let state = CachedState::new(PapyrusReader::new(reader, block_context.block_number));
        let executed_class_hashes = HashSet::<ClassHash>::new();
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

pub struct PyGeneralConfig {
    pub starknet_os_config: PyOsConfig,
    pub sequencer_address: PyFelt,
    pub cairo_resource_fee_weights: Arc<HashMap<String, f64>>,
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
}

impl FromPyObject<'_> for PyGeneralConfig {
    fn extract(general_config: &PyAny) -> PyResult<Self> {
        let starknet_os_config = general_config.getattr("starknet_os_config")?.extract()?;
        let sequencer_address = general_config.getattr("sequencer_address")?.extract()?;
        let cairo_resource_fee_weights: HashMap<String, f64> =
            general_config.getattr("cairo_resource_fee_weights")?.extract()?;

        let cairo_resource_fee_weights = Arc::new(cairo_resource_fee_weights);
        let invoke_tx_max_n_steps = general_config.getattr("invoke_tx_max_n_steps")?.extract()?;
        let validate_max_n_steps = general_config.getattr("validate_max_n_steps")?.extract()?;

        Ok(Self {
            starknet_os_config,
            sequencer_address,
            cairo_resource_fee_weights,
            invoke_tx_max_n_steps,
            validate_max_n_steps,
        })
    }
}

#[derive(FromPyObject)]
pub struct PyOsConfig {
    #[pyo3(from_py_with = "int_to_chain_id")]
    pub chain_id: ChainId,
    pub fee_token_address: PyFelt,
}

pub fn py_block_context(
    general_config: PyGeneralConfig,
    block_info: &PyAny,
    max_recursion_depth: usize,
) -> NativeBlockifierResult<BlockContext> {
    let starknet_os_config = general_config.starknet_os_config;
    let block_number = BlockNumber(py_attr(block_info, "block_number")?);
    let block_context = BlockContext {
        chain_id: starknet_os_config.chain_id,
        block_number,
        block_timestamp: BlockTimestamp(py_attr(block_info, "block_timestamp")?),
        sequencer_address: ContractAddress::try_from(general_config.sequencer_address.0)?,
        fee_token_address: ContractAddress::try_from(starknet_os_config.fee_token_address.0)?,
        vm_resource_fee_cost: general_config.cairo_resource_fee_weights,
        gas_price: py_attr(block_info, "gas_price")?,
        invoke_tx_max_n_steps: general_config.invoke_tx_max_n_steps,
        validate_max_n_steps: general_config.validate_max_n_steps,
        max_recursion_depth,
    };

    Ok(block_context)
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
