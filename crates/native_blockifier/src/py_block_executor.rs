use std::collections::HashMap;
use std::sync::Arc;

use blockifier::block::{
    pre_process_block as pre_process_block_blockifier, BlockInfo, BlockNumberHashPair, GasPrices,
};
use blockifier::block_execution::transaction_executor::TransactionExecutor;
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use blockifier::state::cached_state::{CachedState, GlobalContractCache};
use blockifier::state::state_api::State;
use blockifier::transaction::objects::TransactionExecutionInfo;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::versioned_constants::VersionedConstants;
use pyo3::prelude::*;
use serde::Serialize;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress};
use starknet_api::hash::StarkFelt;

use crate::errors::{
    InvalidNativeBlockifierInputError, NativeBlockifierError, NativeBlockifierInputError,
    NativeBlockifierResult,
};
use crate::py_state_diff::{PyBlockInfo, PyStateDiff};
use crate::py_transaction::{py_tx, PyClassInfo};
use crate::py_transaction_execution_info::PyBouncerInfo;
use crate::py_utils::{int_to_chain_id, py_attr, versioned_constants_with_overrides, PyFelt};
use crate::state_readers::papyrus_state::PapyrusReader;
use crate::storage::{PapyrusStorage, Storage, StorageConfig};

pub(crate) type RawTransactionExecutionInfo = Vec<u8>;

#[cfg(test)]
#[path = "py_block_executor_test.rs"]
mod py_block_executor_test;

const MAX_STEPS_PER_TX: u32 = 4_000_000;
const MAX_VALIDATE_STEPS_PER_TX: u32 = 1_000_000;

#[pyclass]
#[derive(Debug, Serialize)]
pub(crate) struct TypedTransactionExecutionInfo {
    #[serde(flatten)]
    pub info: TransactionExecutionInfo,
    pub tx_type: String,
}

#[pyclass]
pub struct PyBlockExecutor {
    pub general_config: PyGeneralConfig,
    pub versioned_constants: VersionedConstants,
    pub tx_executor: Option<TransactionExecutor<PapyrusReader>>,
    /// `Send` trait is required for `pyclass` compatibility as Python objects must be threadsafe.
    pub storage: Box<dyn Storage + Send>,
    pub global_contract_cache: GlobalContractCache,
}

#[pymethods]
impl PyBlockExecutor {
    #[new]
    #[pyo3(signature = (general_config, validate_max_n_steps, max_recursion_depth, global_contract_cache_size, target_storage_config))]
    pub fn create(
        general_config: PyGeneralConfig,
        validate_max_n_steps: u32,
        max_recursion_depth: usize,
        global_contract_cache_size: usize,
        target_storage_config: StorageConfig,
    ) -> Self {
        log::debug!("Initializing Block Executor...");
        let storage =
            PapyrusStorage::new(target_storage_config).expect("Failed to initialize storage");
        let versioned_constants =
            versioned_constants_with_overrides(validate_max_n_steps, max_recursion_depth);
        log::debug!("Initialized Block Executor.");

        Self {
            general_config,
            versioned_constants,
            tx_executor: None,
            storage: Box::new(storage),
            global_contract_cache: GlobalContractCache::new(global_contract_cache_size),
        }
    }

    // Transaction Execution API.

    /// Initializes the transaction executor for the given block.
    #[pyo3(signature = (next_block_info, old_block_number_and_hash))]
    fn setup_block_execution(
        &mut self,
        next_block_info: PyBlockInfo,
        old_block_number_and_hash: Option<(u64, PyFelt)>,
    ) -> NativeBlockifierResult<()> {
        let papyrus_reader = self.get_aligned_reader(next_block_info.block_number);
        let global_contract_cache = self.global_contract_cache.clone();
        let mut state = CachedState::new(papyrus_reader, global_contract_cache);
        let block_context = pre_process_block(
            &mut state,
            old_block_number_and_hash,
            &self.general_config,
            &next_block_info,
            &self.versioned_constants,
        )?;

        let tx_executor = TransactionExecutor::new(state, block_context);
        self.tx_executor = Some(tx_executor);

        Ok(())
    }

    fn teardown_block_execution(&mut self) {
        self.tx_executor = None;
    }

    #[pyo3(signature = (tx, optional_py_class_info))]
    pub fn execute(
        &mut self,
        tx: &PyAny,
        optional_py_class_info: Option<PyClassInfo>,
    ) -> NativeBlockifierResult<(RawTransactionExecutionInfo, PyBouncerInfo)> {
        let charge_fee = true;
        let tx_type: &str = tx.getattr("tx_type")?.getattr("name")?.extract()?;
        let tx: Transaction = py_tx(tx, optional_py_class_info)?;
        let (tx_execution_info, bouncer_info) = self.tx_executor().execute(tx, charge_fee)?;
        let typed_tx_execution_info =
            TypedTransactionExecutionInfo { info: tx_execution_info, tx_type: tx_type.to_string() };
        let raw_tx_execution_info = serde_json::to_vec(&typed_tx_execution_info)?;
        let py_bouncer_info = PyBouncerInfo::from(bouncer_info);

        Ok((raw_tx_execution_info, py_bouncer_info))
    }

    /// Returns the state diff and a list of contract class hash with the corresponding list of
    /// visited PC values.
    pub fn finalize(&mut self, is_pending_block: bool) -> (PyStateDiff, Vec<(PyFelt, Vec<usize>)>) {
        log::debug!("Finalizing execution...");
        let (commitment_state_diff, visited_pcs) = self.tx_executor().finalize(is_pending_block);
        let visited_pcs = visited_pcs
            .into_iter()
            .map(|(class_hash, class_visited_pcs_vec)| {
                (PyFelt::from(class_hash), class_visited_pcs_vec)
            })
            .collect();
        let finalized_state = (PyStateDiff::from(commitment_state_diff), visited_pcs);
        log::debug!("Finalized execution.");

        finalized_state
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
        use blockifier::state::cached_state::GLOBAL_CONTRACT_CACHE_SIZE_FOR_TEST;
        Self {
            storage: Box::new(PapyrusStorage::new_for_testing(
                path,
                &general_config.starknet_os_config.chain_id,
            )),
            general_config,
            versioned_constants: VersionedConstants::latest_constants().clone(),
            tx_executor: None,
            global_contract_cache: GlobalContractCache::new(GLOBAL_CONTRACT_CACHE_SIZE_FOR_TEST),
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
        use blockifier::state::cached_state::GLOBAL_CONTRACT_CACHE_SIZE_FOR_TEST;
        Self {
            storage: Box::new(storage),
            general_config: PyGeneralConfig::default(),
            versioned_constants: VersionedConstants::latest_constants().clone(),
            tx_executor: None,
            global_contract_cache: GlobalContractCache::new(GLOBAL_CONTRACT_CACHE_SIZE_FOR_TEST),
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

impl TryFrom<PyOsConfig> for ChainInfo {
    type Error = NativeBlockifierError;

    fn try_from(py_os_config: PyOsConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            chain_id: py_os_config.chain_id,
            fee_token_addresses: FeeTokenAddresses {
                eth_fee_token_address: ContractAddress::try_from(
                    py_os_config.deprecated_fee_token_address.0,
                )?,
                strk_fee_token_address: ContractAddress::try_from(
                    py_os_config.fee_token_address.0,
                )?,
            },
        })
    }
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

pub fn into_block_context_args(
    general_config: &PyGeneralConfig,
    block_info: &PyBlockInfo,
) -> NativeBlockifierResult<(BlockInfo, ChainInfo)> {
    let chain_info: ChainInfo = general_config.starknet_os_config.clone().try_into()?;
    let block_info = BlockInfo {
        block_number: BlockNumber(block_info.block_number),
        block_timestamp: BlockTimestamp(block_info.block_timestamp),
        sequencer_address: ContractAddress::try_from(block_info.sequencer_address.0)?,
        gas_prices: GasPrices {
            eth_l1_gas_price: block_info.l1_gas_price.price_in_wei.try_into().map_err(|_| {
                NativeBlockifierInputError::InvalidNativeBlockifierInputError(
                    InvalidNativeBlockifierInputError::InvalidGasPriceWei(
                        block_info.l1_gas_price.price_in_wei,
                    ),
                )
            })?,
            strk_l1_gas_price: block_info.l1_gas_price.price_in_fri.try_into().map_err(|_| {
                NativeBlockifierInputError::InvalidNativeBlockifierInputError(
                    InvalidNativeBlockifierInputError::InvalidGasPriceFri(
                        block_info.l1_gas_price.price_in_fri,
                    ),
                )
            })?,
            eth_l1_data_gas_price: block_info.l1_data_gas_price.price_in_wei.try_into().map_err(
                |_| {
                    NativeBlockifierInputError::InvalidNativeBlockifierInputError(
                        InvalidNativeBlockifierInputError::InvalidDataGasPriceWei(
                            block_info.l1_data_gas_price.price_in_wei,
                        ),
                    )
                },
            )?,
            strk_l1_data_gas_price: block_info.l1_data_gas_price.price_in_fri.try_into().map_err(
                |_| {
                    NativeBlockifierInputError::InvalidNativeBlockifierInputError(
                        InvalidNativeBlockifierInputError::InvalidDataGasPriceFri(
                            block_info.l1_data_gas_price.price_in_fri,
                        ),
                    )
                },
            )?,
        },
        use_kzg_da: block_info.use_kzg_da,
    };

    Ok((block_info, chain_info))
}

// Executes block pre-processing; see `block_execution::pre_process_block` documentation.
fn pre_process_block(
    state: &mut dyn State,
    old_block_number_and_hash: Option<(u64, PyFelt)>,
    general_config: &PyGeneralConfig,
    block_info: &PyBlockInfo,
    versioned_constants: &VersionedConstants,
) -> NativeBlockifierResult<BlockContext> {
    let old_block_number_and_hash = old_block_number_and_hash
        .map(|(block_number, block_hash)| BlockNumberHashPair::new(block_number, block_hash.0));

    // Input validation.
    if versioned_constants.invoke_tx_max_n_steps > MAX_STEPS_PER_TX {
        Err(NativeBlockifierInputError::MaxStepsPerTxOutOfRange(
            versioned_constants.invoke_tx_max_n_steps,
        ))?;
    } else if versioned_constants.validate_max_n_steps > MAX_VALIDATE_STEPS_PER_TX {
        Err(NativeBlockifierInputError::MaxValidateStepsPerTxOutOfRange(
            versioned_constants.validate_max_n_steps,
        ))?;
    }

    let (block_info, chain_info) = into_block_context_args(general_config, block_info)?;
    let block_context = pre_process_block_blockifier(
        state,
        old_block_number_and_hash,
        block_info,
        chain_info,
        versioned_constants.clone(),
    )?;

    Ok(block_context)
}
