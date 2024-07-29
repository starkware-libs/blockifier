use std::collections::HashMap;

use blockifier::blockifier::block::{
    pre_process_block as pre_process_block_blockifier, BlockInfo, BlockNumberHashPair, GasPrices,
};
use blockifier::blockifier::config::TransactionExecutorConfig;
use blockifier::blockifier::transaction_executor::{TransactionExecutor, TransactionExecutorError};
use blockifier::bouncer::BouncerConfig;
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use blockifier::execution::call_info::CallInfo;
use blockifier::state::cached_state::CachedState;
use blockifier::state::global_cache::GlobalContractCache;
use blockifier::state::state_api::State;
use blockifier::transaction::objects::{GasVector, ResourcesMapping, TransactionExecutionInfo};
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::versioned_constants::VersionedConstants;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};
use pyo3::{FromPyObject, PyAny, Python};
use serde::Serialize;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Fee;

use crate::errors::{
    InvalidNativeBlockifierInputError, NativeBlockifierError, NativeBlockifierInputError,
    NativeBlockifierResult,
};
use crate::py_objects::{PyBouncerConfig, PyConcurrencyConfig};
use crate::py_state_diff::{PyBlockInfo, PyStateDiff};
use crate::py_transaction::{get_py_tx_type, py_tx, PyClassInfo, PY_TX_PARSING_ERR};
use crate::py_utils::{int_to_chain_id, PyFelt};
use crate::state_readers::papyrus_state::PapyrusReader;
use crate::storage::{PapyrusStorage, Storage, StorageConfig};

pub(crate) type RawTransactionExecutionResult = Vec<u8>;
pub(crate) type PyVisitedSegmentsMapping = Vec<(PyFelt, Vec<usize>)>;

#[cfg(test)]
#[path = "py_block_executor_test.rs"]
mod py_block_executor_test;

const MAX_STEPS_PER_TX: u32 = 4_000_000;
const MAX_VALIDATE_STEPS_PER_TX: u32 = 1_000_000;
const RESULT_SERIALIZE_ERR: &str = "Failed serializing execution info.";

/// Stripped down `TransactionExecutionInfo` for Python serialization, containing only the required
/// fields.
#[derive(Debug, Serialize)]
pub(crate) struct ThinTransactionExecutionInfo {
    pub validate_call_info: Option<CallInfo>,
    pub execute_call_info: Option<CallInfo>,
    pub fee_transfer_call_info: Option<CallInfo>,
    pub actual_fee: Fee,
    pub da_gas: GasVector,
    pub actual_resources: ResourcesMapping,
    pub revert_error: Option<String>,
}

impl ThinTransactionExecutionInfo {
    pub fn from_tx_execution_info(
        block_context: &BlockContext,
        tx_execution_info: TransactionExecutionInfo,
    ) -> Self {
        Self {
            validate_call_info: tx_execution_info.validate_call_info,
            execute_call_info: tx_execution_info.execute_call_info,
            fee_transfer_call_info: tx_execution_info.fee_transfer_call_info,
            actual_fee: tx_execution_info.actual_fee,
            da_gas: tx_execution_info.da_gas,
            actual_resources: tx_execution_info.actual_resources.to_resources_mapping(
                block_context.versioned_constants(),
                block_context.block_info().use_kzg_da,
                true,
            ),
            revert_error: tx_execution_info.revert_error,
        }
    }
}

#[pyclass]
#[derive(Debug, Serialize)]
pub(crate) struct TypedTransactionExecutionInfo {
    #[serde(flatten)]
    pub info: ThinTransactionExecutionInfo,
    pub tx_type: String,
}

impl TypedTransactionExecutionInfo {
    pub fn from_tx_execution_info(
        block_context: &BlockContext,
        tx_execution_info: TransactionExecutionInfo,
        tx_type: String,
    ) -> Self {
        TypedTransactionExecutionInfo {
            info: ThinTransactionExecutionInfo::from_tx_execution_info(
                block_context,
                tx_execution_info,
            ),
            tx_type,
        }
    }

    pub fn serialize(self) -> RawTransactionExecutionResult {
        serde_json::to_vec(&self).expect(RESULT_SERIALIZE_ERR)
    }
}

#[pyclass]
pub struct PyBlockExecutor {
    pub bouncer_config: BouncerConfig,
    pub tx_executor_config: TransactionExecutorConfig,
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
    #[pyo3(signature = (bouncer_config, concurrency_config, general_config, validate_max_n_steps, max_recursion_depth, global_contract_cache_size, target_storage_config))]
    pub fn create(
        bouncer_config: PyBouncerConfig,
        concurrency_config: PyConcurrencyConfig,
        general_config: PyGeneralConfig,
        validate_max_n_steps: u32,
        max_recursion_depth: usize,
        global_contract_cache_size: usize,
        target_storage_config: StorageConfig,
    ) -> Self {
        log::debug!("Initializing Block Executor...");
        let storage =
            PapyrusStorage::new(target_storage_config).expect("Failed to initialize storage");
        let versioned_constants = VersionedConstants::latest_constants_with_overrides(
            validate_max_n_steps,
            max_recursion_depth,
        );
        log::debug!("Initialized Block Executor.");

        Self {
            bouncer_config: bouncer_config.into(),
            tx_executor_config: TransactionExecutorConfig {
                concurrency_config: concurrency_config.into(),
            },
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
        let mut state = CachedState::new(papyrus_reader);
        let block_context = pre_process_block(
            &mut state,
            old_block_number_and_hash,
            &self.general_config,
            &next_block_info,
            &self.versioned_constants,
            self.tx_executor_config.concurrency_config.enabled,
        )?;

        let tx_executor = TransactionExecutor::new(
            state,
            block_context,
            self.bouncer_config.clone(),
            self.tx_executor_config.clone(),
        );
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
    ) -> NativeBlockifierResult<Py<PyBytes>> {
        let charge_fee = true;
        let tx_type: String = get_py_tx_type(tx).expect(PY_TX_PARSING_ERR).to_string();
        let tx: Transaction = py_tx(tx, optional_py_class_info).expect(PY_TX_PARSING_ERR);
        let tx_execution_info = self.tx_executor().execute(&tx, charge_fee)?;
        let typed_tx_execution_info = TypedTransactionExecutionInfo::from_tx_execution_info(
            &self.tx_executor().block_context,
            tx_execution_info,
            tx_type,
        );

        // Convert to PyBytes:
        let raw_tx_execution_info = Python::with_gil(|py| {
            let bytes_tx_execution_info = typed_tx_execution_info.serialize();
            PyBytes::new(py, &bytes_tx_execution_info).into()
        });

        Ok(raw_tx_execution_info)
    }

    /// Executes the given transactions on the Blockifier state.
    /// Stops if and when there is no more room in the block, and returns the executed transactions'
    /// results as a PyList of (success (bool), serialized result (bytes)) tuples.
    #[pyo3(signature = (txs_with_class_infos))]
    pub fn execute_txs(
        &mut self,
        txs_with_class_infos: Vec<(&PyAny, Option<PyClassInfo>)>,
    ) -> Py<PyList> {
        let charge_fee = true;

        // Parse Py transactions.
        let (tx_types, txs): (Vec<String>, Vec<Transaction>) = txs_with_class_infos
            .into_iter()
            .map(|(tx, optional_py_class_info)| {
                (
                    get_py_tx_type(tx).expect(PY_TX_PARSING_ERR).to_string(),
                    py_tx(tx, optional_py_class_info).expect(PY_TX_PARSING_ERR),
                )
            })
            .unzip();

        // Run.
        let results = self.tx_executor().execute_txs(&txs, charge_fee);

        // Process results.
        // TODO(Yoni, 15/5/2024): serialize concurrently.
        let block_context = &self.tx_executor().block_context;
        let serialized_results: Vec<(bool, RawTransactionExecutionResult)> = results
            .into_iter()
            // Note: there might be less results than txs (if there is no room for all of them).
            .zip(tx_types)
            .map(|(result, tx_type)| match result {
                Ok(tx_execution_info) => (
                    true,
                    TypedTransactionExecutionInfo::from_tx_execution_info(
                        block_context,
                        tx_execution_info,
                        tx_type,
                    )
                    .serialize(),
                ),
                Err(error) => (false, serialize_failure_reason(error)),
            })
            .collect();

        // Convert to Py types and allocate it on Python's heap, to be visible for Python's
        // garbage collector.
        Python::with_gil(|py| {
            let py_serialized_results: Vec<(bool, Py<PyBytes>)> = serialized_results
                .into_iter()
                .map(|(success, execution_result)| {
                    // Note that PyList converts the inner elements recursively, yet the default
                    // conversion of the execution result (Vec<u8>) is to a list of integers, which
                    // might be less efficient than bytes.
                    (success, PyBytes::new(py, &execution_result).into())
                })
                .collect();
            PyList::new(py, py_serialized_results).into()
        })
    }

    /// Returns the state diff and a list of contract class hash with the corresponding list of
    /// visited segment values.
    pub fn finalize(&mut self) -> NativeBlockifierResult<(PyStateDiff, PyVisitedSegmentsMapping)> {
        log::debug!("Finalizing execution...");
        let (commitment_state_diff, visited_pcs) = self.tx_executor().finalize()?;
        let visited_pcs = visited_pcs
            .into_iter()
            .map(|(class_hash, class_visited_pcs_vec)| {
                (PyFelt::from(class_hash), class_visited_pcs_vec)
            })
            .collect();
        let finalized_state = (PyStateDiff::from(commitment_state_diff), visited_pcs);
        log::debug!("Finalized execution.");

        Ok(finalized_state)
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
    #[pyo3(signature = (concurrency_config, general_config, path, max_state_diff_size))]
    #[staticmethod]
    fn create_for_testing(
        concurrency_config: PyConcurrencyConfig,
        general_config: PyGeneralConfig,
        path: std::path::PathBuf,
        max_state_diff_size: usize,
    ) -> Self {
        use blockifier::bouncer::BouncerWeights;
        use blockifier::state::global_cache::GLOBAL_CONTRACT_CACHE_SIZE_FOR_TEST;
        Self {
            bouncer_config: BouncerConfig {
                block_max_capacity: BouncerWeights {
                    state_diff_size: max_state_diff_size,
                    ..BouncerWeights::max(false)
                },
                block_max_capacity_with_keccak: BouncerWeights {
                    state_diff_size: max_state_diff_size,
                    ..BouncerWeights::max(true)
                },
            },
            tx_executor_config: TransactionExecutorConfig {
                concurrency_config: concurrency_config.into(),
            },
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
        PapyrusReader::new(
            self.storage.reader().clone(),
            BlockNumber(next_block_number),
            self.global_contract_cache.clone(),
        )
    }

    #[cfg(any(feature = "testing", test))]
    pub fn create_for_testing_with_storage(storage: impl Storage + Send + 'static) -> Self {
        use blockifier::state::global_cache::GLOBAL_CONTRACT_CACHE_SIZE_FOR_TEST;
        Self {
            bouncer_config: BouncerConfig::max(),
            tx_executor_config: TransactionExecutorConfig::default(),
            storage: Box::new(storage),
            general_config: PyGeneralConfig::default(),
            versioned_constants: VersionedConstants::latest_constants().clone(),
            tx_executor: None,
            global_contract_cache: GlobalContractCache::new(GLOBAL_CONTRACT_CACHE_SIZE_FOR_TEST),
        }
    }
}

#[derive(Default, FromPyObject)]
pub struct PyGeneralConfig {
    pub starknet_os_config: PyOsConfig,
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
}

#[derive(Clone, FromPyObject)]
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

// Executes block pre-processing; see `blockifier::blockifier::block::pre_process_block`
// documentation.
fn pre_process_block(
    state: &mut dyn State,
    old_block_number_and_hash: Option<(u64, PyFelt)>,
    general_config: &PyGeneralConfig,
    block_info: &PyBlockInfo,
    versioned_constants: &VersionedConstants,
    concurrency_mode: bool,
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
        concurrency_mode,
    )?;

    Ok(block_context)
}

fn serialize_failure_reason(error: TransactionExecutorError) -> RawTransactionExecutionResult {
    // TODO(Yoni, 1/7/2024): re-consider this serialization.
    serde_json::to_vec(&format!("{}", error)).expect(RESULT_SERIALIZE_ERR)
}
