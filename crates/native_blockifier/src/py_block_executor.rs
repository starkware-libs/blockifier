use std::collections::HashMap;
use std::sync::Arc;

use blockifier::block_context::BlockContext;
use pyo3::prelude::*;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress};

use crate::errors::NativeBlockifierResult;
use crate::py_state_diff::{PyBlockInfo, PyStateDiff};
use crate::py_transaction_execution_info::{PyTransactionExecutionInfo, PyVmExecutionResources};
use crate::py_transaction_executor::TransactionExecutor;
use crate::py_utils::{int_to_chain_id, PyFelt};
use crate::storage::Storage;

#[pyclass]
pub struct PyBlockExecutor {
    pub general_config: PyGeneralConfig,
    pub max_recursion_depth: usize,
    pub tx_executor: Option<TransactionExecutor>,
    // TODO: add TransactionExecutor and Storage as fields.
}

#[pymethods]
impl PyBlockExecutor {
    #[new]
    #[args(general_config, max_recursion_depth)]
    pub fn create(general_config: PyGeneralConfig, max_recursion_depth: usize) -> Self {
        let tx_executor = None;
        log::debug!("Initialized Blockifier storage.");
        Self { general_config, max_recursion_depth, tx_executor }
    }

    #[args(general_config)]
    #[staticmethod]
    fn create_for_testing(general_config: PyGeneralConfig) -> Self {
        Self { general_config, max_recursion_depth: 50, tx_executor: None }
    }

    /// Initializes the transaction executor for the given block.
    #[args(storage, block_info)]
    fn setup_block_execution(
        &mut self,
        storage: &Storage,
        block_info: PyBlockInfo,
    ) -> NativeBlockifierResult<()> {
        let tx_executor = TransactionExecutor::new(
            storage,
            &self.general_config,
            block_info,
            self.max_recursion_depth,
        )?;
        self.tx_executor = Some(tx_executor);
        Ok(())
    }

    fn teardown_block_execution(&mut self) {
        self.tx_executor = None;
    }

    /// Deallocate the transaction executor and close storage connections.
    pub fn close(&mut self) {
        log::debug!("Closing Blockifier storage.");
        // If the block was not finalized (due to some exception occuring _in Python_), we need
        // to deallocate the transaction executor here to prevent leaks.
        self.teardown_block_execution();
    }

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

    pub fn finalize(&mut self) -> PyStateDiff {
        log::debug!("Finalizing execution...");
        let finalized_state = self.tx_executor().finalize();
        log::debug!("Finalized execution.");

        finalized_state
    }

    #[args(old_block_number_and_hash)]
    pub fn pre_process_block(
        &mut self,
        old_block_number_and_hash: Option<(u64, PyFelt)>,
    ) -> NativeBlockifierResult<()> {
        self.tx_executor().pre_process_block(old_block_number_and_hash)
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

#[derive(FromPyObject, Clone)]
pub struct PyOsConfig {
    #[pyo3(from_py_with = "int_to_chain_id")]
    pub chain_id: ChainId,
    pub fee_token_address: PyFelt,
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
        sequencer_address: ContractAddress::try_from(general_config.sequencer_address.0)?,
        fee_token_address: ContractAddress::try_from(starknet_os_config.fee_token_address.0)?,
        vm_resource_fee_cost: general_config.cairo_resource_fee_weights.clone(),
        gas_price: block_info.gas_price,
        invoke_tx_max_n_steps: general_config.invoke_tx_max_n_steps,
        validate_max_n_steps: general_config.validate_max_n_steps,
        max_recursion_depth,
    };

    Ok(block_context)
}
