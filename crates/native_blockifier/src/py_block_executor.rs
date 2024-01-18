use std::collections::HashMap;
use std::sync::Arc;

use blockifier::block_context::{BlockContext, BlockInfo, FeeTokenAddresses};
use blockifier::state::cached_state::GlobalContractCache;
use pyo3::prelude::*;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress};
use starknet_api::hash::StarkFelt;

use crate::errors::NativeBlockifierResult;
use crate::py_state_diff::{PyBlockInfo, PyStateDiff};
use crate::py_transaction_execution_info::{PyBouncerInfo, PyTransactionExecutionInfo};
use crate::py_utils::{int_to_chain_id, py_attr, PyFelt};
use crate::state_readers::papyrus_state::PapyrusReader;
use crate::storage::{PapyrusStorage, Storage, StorageConfig};
use crate::transaction_executor::TransactionExecutor;

#[cfg(test)]
#[path = "py_block_executor_test.rs"]
mod py_block_executor_test;

#[pyclass]
pub struct PyBlockExecutor {
    pub general_config: PyGeneralConfig,
    pub max_recursion_depth: usize,
    pub tx_executor: Option<TransactionExecutor<PapyrusReader>>,
    /// `Send` trait is required for `pyclass` compatibility as Python objects must be threadsafe.
    pub storage: Box<dyn Storage + Send>,
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
        let storage =
            PapyrusStorage::new(target_storage_config).expect("Failed to initialize storage");

        log::debug!("Initialized Block Executor.");
        Self {
            general_config,
            max_recursion_depth,
            tx_executor,
            storage: Box::new(storage),
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
        let papyrus_reader = self.get_aligned_reader(next_block_info.block_number);

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
    ) -> NativeBlockifierResult<(PyTransactionExecutionInfo, PyBouncerInfo)> {
        let charge_fee = true;
        self.tx_executor().execute(tx, raw_contract_class, charge_fee)
    }

    /// Returns the state diff and a list of contract class hash with the corresponding list of
    /// visited PC values.
    pub fn finalize(&mut self, is_pending_block: bool) -> (PyStateDiff, Vec<(PyFelt, Vec<usize>)>) {
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
    fn get_block_id_at_target(&self, block_number: u64) -> NativeBlockifierResult<Option<PyFelt>> {
        let optional_block_id_bytes = self.storage.get_block_id(block_number)?;
        let Some(block_id_bytes) = optional_block_id_bytes else { return Ok(None) };

        let mut block_id_fixed_bytes = [0_u8; 32];
        block_id_fixed_bytes.copy_from_slice(&block_id_bytes);

        Ok(Some(PyFelt(StarkFelt::new(block_id_fixed_bytes)?)))
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
        // Clear global class cache, to peroperly revert classes declared in the reverted block.
        self.global_contract_cache.clear();
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

    #[cfg(any(feature = "testing", test))]
    #[pyo3(signature = (general_config, path))]
    #[staticmethod]
    fn create_for_testing(general_config: PyGeneralConfig, path: std::path::PathBuf) -> Self {
        Self {
            storage: Box::new(PapyrusStorage::new_for_testing(
                path,
                &general_config.starknet_os_config.chain_id,
            )),
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

    fn get_aligned_reader(&self, next_block_number: u64) -> PapyrusReader {
        // Full-node storage must be aligned to the Python storage before initializing a reader.
        self.storage.validate_aligned(next_block_number);
        PapyrusReader::new(self.storage.reader().clone(), BlockNumber(next_block_number))
    }

    #[cfg(any(feature = "testing", test))]
    pub fn create_for_testing_with_storage(storage: impl Storage + Send + 'static) -> Self {
        Self {
            storage: Box::new(storage),
            general_config: PyGeneralConfig::default(),
            max_recursion_depth: 50,
            tx_executor: None,
            global_contract_cache: GlobalContractCache::default(),
        }
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
        let starknet_os_config: PyOsConfig = py_attr(general_config, "starknet_os_config")?;
        let cairo_resource_fee_weights: HashMap<String, f64> =
            py_attr(general_config, "cairo_resource_fee_weights")?;
        let cairo_resource_fee_weights = Arc::new(cairo_resource_fee_weights);
        let invoke_tx_max_n_steps: u32 = py_attr(general_config, "invoke_tx_max_n_steps")?;
        let validate_max_n_steps: u32 = py_attr(general_config, "validate_max_n_steps")?;

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
    let block_context = BlockContext {
        block_info: BlockInfo {
            chain_id: starknet_os_config.chain_id,
            block_number: BlockNumber(block_info.block_number),
            block_timestamp: BlockTimestamp(block_info.block_timestamp),
            sequencer_address: ContractAddress::try_from(block_info.sequencer_address.0)?,
            fee_token_addresses: FeeTokenAddresses {
                eth_fee_token_address: ContractAddress::try_from(
                    starknet_os_config.deprecated_fee_token_address.0,
                )?,
                strk_fee_token_address: ContractAddress::try_from(
                    starknet_os_config.fee_token_address.0,
                )?,
            },
            vm_resource_fee_cost: general_config.cairo_resource_fee_weights.clone(),
            gas_prices: block_info.gas_prices.into(),
            use_kzg_da: block_info.use_kzg_da,
            invoke_tx_max_n_steps: general_config.invoke_tx_max_n_steps,
            validate_max_n_steps: general_config.validate_max_n_steps,
            max_recursion_depth,
        },
    };

    Ok(block_context)
}
