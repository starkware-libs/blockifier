use std::collections::HashMap;
use std::sync::Arc;

use blockifier::block_context::BlockContext;
use blockifier::state::cached_state::GlobalContractCache;
use pyo3::prelude::*;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress};

use crate::errors::NativeBlockifierResult;
use crate::papyrus_state::PapyrusReader;
use crate::py_state_diff::{PyBlockInfo, PyStateDiff};
use crate::py_transaction_execution_info::{PyTransactionExecutionInfo, PyVmExecutionResources};
use crate::py_utils::{int_to_chain_id, PyFelt};
use crate::storage::{Storage, StorageConfig};
use crate::transaction_executor::TransactionExecutor;

#[cfg(test)]
#[path = "py_block_executor_test.rs"]
mod py_block_executor_test;

#[pyclass]
pub struct PyBlockExecutor {
    pub general_config: PyGeneralConfig,
    pub max_recursion_depth: usize,
    pub tx_executor: Option<TransactionExecutor<PapyrusReader>>,
    pub storage: Storage,
    pub global_contract_cache: GlobalContractCache,
}

#[pymethods]
impl PyBlockExecutor {
    #[new]
    #[pyo3(signature = (general_config, max_recursion_depth, target_storage_config))]
    pub fn create(
        general_config: PyGeneralConfig,
        max_recursion_depth: usize,
        target_storage_config: StorageConfig,
    ) -> Self {
        log::debug!("Initializing Block Executor...");
        let tx_executor = None;
        let storage = Storage::new(target_storage_config).expect("Failed to initialize storage");

        log::debug!("Initialized Block Executor.");
        Self {
            general_config,
            max_recursion_depth,
            tx_executor,
            storage,
            global_contract_cache: GlobalContractCache::default(),
        }
    }

    // Transaction Execution API.

    /// Initializes the transaction executor for the given block.
    #[pyo3(signature = (next_block_info))]
    fn setup_block_execution(
        &mut self,
        next_block_info: PyBlockInfo,
    ) -> NativeBlockifierResult<()> {
        // Full-node storage must be aligned to the Python storage before initializing a reader.
        self.storage.validate_aligned(next_block_info.block_number);
        let papyrus_reader = PapyrusReader::new(
            self.storage.reader().clone(),
            BlockNumber(next_block_info.block_number),
        );

        let tx_executor = TransactionExecutor::new(
            papyrus_reader,
            &self.general_config,
            next_block_info,
            self.max_recursion_depth,
            self.global_contract_cache.clone(),
        )?;
        self.tx_executor = Some(tx_executor);

        Ok(())
    }

    fn teardown_block_execution(&mut self) {
        self.tx_executor = None;
    }

    #[pyo3(signature = (tx, raw_contract_class))]
    pub fn execute(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
    ) -> NativeBlockifierResult<(PyTransactionExecutionInfo, PyVmExecutionResources)> {
        let charge_fee = true;
        self.tx_executor().execute(tx, raw_contract_class, charge_fee)
    }

    pub fn finalize(&mut self, is_pending_block: bool) -> PyStateDiff {
        log::debug!("Finalizing execution...");
        let finalized_state = self.tx_executor().finalize(is_pending_block);
        log::debug!("Finalized execution.");

        finalized_state
    }

    #[pyo3(signature = (old_block_number_and_hash))]
    pub fn pre_process_block(
        &mut self,
        old_block_number_and_hash: Option<(u64, PyFelt)>,
    ) -> NativeBlockifierResult<()> {
        self.tx_executor().pre_process_block(old_block_number_and_hash)
    }

    pub fn commit_tx(&mut self) {
        self.tx_executor().commit()
    }

    pub fn abort_tx(&mut self) {
        self.tx_executor().abort()
    }

    // Storage Alignment API.

    /// Appends state diff and block header into Papyrus storage.
    // Previous block ID can either be a block hash (starting from a Papyrus snapshot), or a
    // sequential ID (throughout sequencing).
    #[pyo3(signature = (
        block_id,
        previous_block_id,
        py_block_info,
        py_state_diff,
        declared_class_hash_to_class,
        deprecated_declared_class_hash_to_class
    ))]
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
    #[pyo3(signature = (block_number))]
    fn get_block_id_at_target(&self, block_number: u64) -> NativeBlockifierResult<Option<u64>> {
        let block_id_bytes = self.storage.get_block_id(block_number)?;
        let block_id_u64 = block_id_bytes.map(|block_id_bytes| {
            u64::from_be_bytes(block_id_bytes[block_id_bytes.len() - 8..].try_into().unwrap())
        });

        Ok(block_id_u64)
    }

    #[pyo3(signature = (source_block_number))]
    pub fn validate_aligned(&self, source_block_number: u64) {
        self.storage.validate_aligned(source_block_number);
    }

    /// Atomically reverts block header and state diff of given block number.
    /// If header exists without a state diff (usually the case), only the header is reverted.
    /// (this is true for every partial existence of information at tables).
    #[pyo3(signature = (block_number))]
    pub fn revert_block(&mut self, block_number: u64) -> NativeBlockifierResult<()> {
        self.storage.revert_block(block_number)
    }

    /// Deallocate the transaction executor and close storage connections.
    pub fn close(&mut self) {
        log::debug!("Closing Block Executor.");
        // If the block was not finalized (due to some exception occuring _in Python_), we need
        // to deallocate the transaction executor here to prevent leaks.
        self.teardown_block_execution();
        self.storage.close();
    }

    #[pyo3(signature = (general_config, path))]
    #[staticmethod]
    fn create_for_testing(general_config: PyGeneralConfig, path: std::path::PathBuf) -> Self {
        Self {
            storage: Storage::new_for_testing(path, &general_config.starknet_os_config.chain_id),
            general_config,
            max_recursion_depth: 50,
            tx_executor: None,
            global_contract_cache: GlobalContractCache::default(),
        }
    }
}

impl PyBlockExecutor {
    pub fn tx_executor(&mut self) -> &mut TransactionExecutor<PapyrusReader> {
        self.tx_executor.as_mut().expect("Transaction executor should be initialized")
    }
}

#[derive(Default)]
pub struct PyGeneralConfig {
    pub starknet_os_config: PyOsConfig,
    pub cairo_resource_fee_weights: Arc<HashMap<String, f64>>,
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
}

impl FromPyObject<'_> for PyGeneralConfig {
    fn extract(general_config: &PyAny) -> PyResult<Self> {
        let starknet_os_config = general_config.getattr("starknet_os_config")?.extract()?;
        let cairo_resource_fee_weights: HashMap<String, f64> =
            general_config.getattr("cairo_resource_fee_weights")?.extract()?;

        let cairo_resource_fee_weights = Arc::new(cairo_resource_fee_weights);
        let invoke_tx_max_n_steps = general_config.getattr("invoke_tx_max_n_steps")?.extract()?;
        let validate_max_n_steps = general_config.getattr("validate_max_n_steps")?.extract()?;

        Ok(Self {
            starknet_os_config,
            cairo_resource_fee_weights,
            invoke_tx_max_n_steps,
            validate_max_n_steps,
        })
    }
}

#[derive(FromPyObject, Clone)]
pub struct PyOsConfig {
    #[pyo3(from_py_with = "int_to_chain_id")]
    pub chain_id: ChainId,
    pub deprecated_fee_token_address: PyFelt,
    pub fee_token_address: PyFelt,
}

impl Default for PyOsConfig {
    fn default() -> Self {
        Self {
            chain_id: ChainId("".to_string()),
            deprecated_fee_token_address: Default::default(),
            fee_token_address: Default::default(),
        }
    }
}

pub fn into_block_context(
    general_config: &PyGeneralConfig,
    block_info: PyBlockInfo,
    max_recursion_depth: usize,
) -> NativeBlockifierResult<BlockContext> {
    let starknet_os_config = general_config.starknet_os_config.clone();
    let block_number = BlockNumber(block_info.block_number);
    let block_context = BlockContext {
        chain_id: starknet_os_config.chain_id,
        block_number,
        block_timestamp: BlockTimestamp(block_info.block_timestamp),
        sequencer_address: ContractAddress::try_from(block_info.sequencer_address.0)?,
        deprecated_fee_token_address: ContractAddress::try_from(
            starknet_os_config.deprecated_fee_token_address.0,
        )?,
        fee_token_address: ContractAddress::try_from(starknet_os_config.fee_token_address.0)?,
        vm_resource_fee_cost: general_config.cairo_resource_fee_weights.clone(),
        gas_price: block_info.gas_price,
        invoke_tx_max_n_steps: general_config.invoke_tx_max_n_steps,
        validate_max_n_steps: general_config.validate_max_n_steps,
        max_recursion_depth,
    };

    Ok(block_context)
}
