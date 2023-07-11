use std::collections::HashMap;
use std::sync::Arc;

use pyo3::prelude::*;
use starknet_api::core::ChainId;

use crate::errors::NativeBlockifierResult;
use crate::py_state_diff::{PyBlockInfo, PyStateDiff};
use crate::py_transaction_execution_info::{PyTransactionExecutionInfo, PyVmExecutionResources};
use crate::py_utils::{int_to_chain_id, PyFelt};
use crate::storage::{Storage, StorageConfig};
use crate::transaction_executor::TransactionExecutor;

/// Wraps the transaction executor in an optional, to allow an explicit deallocation of it.
/// The explicit deallocation is needed since PyO3 can't track lifetimes within Python.
// TODO(Gilad): Make Storage and TransactionExecutor into submodules of PyBlockExecutor.
#[pyclass]
pub struct PyBlockExecutor {
    pub tx_executor: Option<TransactionExecutor>,
    pub general_config: PyGeneralConfig,
    pub storage: Storage,
    pub max_recursion_depth: usize,
}

#[pymethods]
impl PyBlockExecutor {
    #[new]
    #[args(general_config, target_storage_config, max_recursion_depth)]
    pub fn create(
        general_config: PyGeneralConfig,
        target_storage_config: StorageConfig,
        max_recursion_depth: usize,
    ) -> Self {
        // Executor is initialized separately for each block, since it needs block-level data.
        let tx_executor = None;
        let storage = Storage::new(target_storage_config).expect("Failed to initialize storage");

        Self { general_config, storage, tx_executor, max_recursion_depth }
    }

    // Transaction execution.

    /// Initializes the transaction executor for the given block.
    #[args(block_info)]
    pub fn start_block(&mut self, block_info: PyBlockInfo) {
        assert!(
            self.tx_executor.is_none(),
            "Transaction executor should not be initialized, previous block NOT finalized"
        );

        let tx_executor = TransactionExecutor::create(
            &self.storage,
            &self.general_config,
            block_info,
            self.max_recursion_depth,
        )
        .expect("Cannot create transaction executor");

        self.tx_executor = Some(tx_executor);
    }

    /// Executes the given transaction on the state maintained by the executor.
    /// Returns the execution trace, together with the compiled class hashes of executed classes
    /// (used for counting purposes).
    #[args(tx, raw_contract_class, enough_room_for_tx)]
    pub fn execute(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
        // This is functools.partial(bouncer.add, tw_written=tx_written).
        enough_room_for_tx: &PyAny,
    ) -> NativeBlockifierResult<(Py<PyTransactionExecutionInfo>, PyVmExecutionResources)> {
        self.tx_executor().execute(tx, raw_contract_class, enough_room_for_tx)
    }

    /// Returns the state diff resulting from executing all transactions contained within the block.
    pub fn finalize(&mut self) -> PyStateDiff {
        log::debug!("Finalizing execution...");
        let py_state_diff = self.tx_executor().finalize();
        log::debug!("Finalized execution.");

        self.end_block();

        py_state_diff
    }

    /// Block pre-processing; see `block_execution::pre_process_block` documentation.
    #[args(old_block_number_and_hash)]
    pub fn pre_process_block(
        &mut self,
        old_block_number_and_hash: Option<(u64, PyFelt)>,
    ) -> NativeBlockifierResult<()> {
        self.tx_executor().pre_process_block(old_block_number_and_hash)
    }

    // Storage alignment.

    /// Appends state diff and block header into Papyrus storage.
    // Previous block ID can either be a block hash (starting from a Papyrus snapshot), or a
    // sequential ID (throughout sequencing).
    #[args(
        block_id,
        previous_block_id,
        py_block_info,
        py_state_diff,
        declared_class_hash_to_class,
        deprecated_declared_class_hash_to_class
    )]
    pub fn append_block(
        &mut self,
        block_id: u64,
        previous_block_id: Option<PyFelt>,
        py_block_info: PyBlockInfo,
        py_state_diff: PyStateDiff,
        declared_class_hash_to_class: HashMap<PyFelt, (PyFelt, String)>,
        deprecated_declared_class_hash_to_class: HashMap<PyFelt, String>,
    ) -> NativeBlockifierResult<()> {
        self.storage.append_block(
            block_id,
            previous_block_id,
            py_block_info,
            py_state_diff,
            declared_class_hash_to_class,
            deprecated_declared_class_hash_to_class,
        )
    }

    /// Returns the next block number, for which block header was not yet appended.
    /// Block header stream is usually ahead of the state diff stream, so this is the indicative
    /// marker.
    pub fn get_header_marker(&self) -> NativeBlockifierResult<u64> {
        self.storage.get_header_marker()
    }

    /// Returns the unique identifier of the given block number in bytes.
    #[args(block_number)]
    fn get_block_id_at_target(&self, block_number: u64) -> NativeBlockifierResult<Option<u64>> {
        let block_id_bytes = self.storage.get_block_id(block_number)?;
        let block_id_u64 = block_id_bytes.map(|block_id_bytes| {
            u64::from_be_bytes(block_id_bytes[block_id_bytes.len() - 8..].try_into().unwrap())
        });

        Ok(block_id_u64)
    }

    #[args(source_block_number)]
    pub fn validate_aligned(&self, source_block_number: u64) {
        self.storage.validate_aligned(source_block_number);
    }

    /// Atomically reverts block header and state diff of given block number.
    /// If header exists without a state diff (usually the case), only the header is reverted.
    /// (this is true for every partial existence of information at tables).
    #[args(block_number)]
    pub fn revert_block(&mut self, block_number: u64) -> NativeBlockifierResult<()> {
        self.storage.revert_block(block_number)
    }

    // Utilities.

    /// Deallocate transaction executor, since this class is shared with Python, the compiler can't
    /// track lifetimes properly.
    fn end_block(&mut self) {
        self.tx_executor = None;
    }

    /// Deallocate the transaction executor and close storage connections.
    pub fn close(&mut self) {
        // If the block was not finalized (due to some exception occuring _in Python_), we need
        // to deallocate the transaction executor here to prevent leaks.
        self.end_block();

        self.storage.close();
    }

    #[args(general_config)]
    #[staticmethod]
    fn create_for_testing(general_config: PyGeneralConfig, path: std::path::PathBuf) -> Self {
        Self {
            general_config,
            storage: Storage::new_for_testing(path),
            max_recursion_depth: 50,
            tx_executor: None,
        }
    }
}

impl PyBlockExecutor {
    pub fn tx_executor(&mut self) -> &mut TransactionExecutor {
        self.tx_executor.as_mut().expect("Transaction executor should be initialized")
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
