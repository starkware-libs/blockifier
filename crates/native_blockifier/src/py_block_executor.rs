use std::collections::HashMap;
use std::sync::Arc;

use blockifier::block_context::BlockContext;
use pyo3::prelude::*;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress};

use crate::errors::NativeBlockifierResult;
use crate::py_transaction_executor::PyTransactionExecutor;
use crate::py_utils::{int_to_chain_id, py_attr, PyFelt};
use crate::storage::Storage;

#[pyclass]
pub struct PyBlockExecutor {
    pub general_config: PyGeneralConfig,
    pub max_recursion_depth: usize,
    // TODO: add TransactionExecutor and Storage as fields.
}

#[pymethods]
impl PyBlockExecutor {
    #[new]
    #[args(general_config, max_recursion_depth)]
    pub fn create(general_config: PyGeneralConfig, max_recursion_depth: usize) -> Self {
        Self { general_config, max_recursion_depth }
    }

    #[args(general_config)]
    #[staticmethod]
    fn create_for_testing(general_config: PyGeneralConfig) -> Self {
        Self { general_config, max_recursion_depth: 50 }
    }

    fn initialize_tx_executor(
        &self,
        storage: &Storage,
        block_info: &PyAny,
    ) -> NativeBlockifierResult<PyTransactionExecutor> {
        PyTransactionExecutor::create(
            storage,
            &self.general_config,
            block_info,
            self.max_recursion_depth,
        )
    }
}

pub struct PyGeneralConfig {
    pub starknet_os_config: PyOsConfig,
    pub sequencer_address: PyFelt,
    pub cairo_resource_fee_weights: Arc<HashMap<String, f64>>,
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
}

impl PyGeneralConfig {
    pub fn into_block_context(
        &self,
        block_info: &PyAny,
        max_recursion_depth: usize,
    ) -> NativeBlockifierResult<BlockContext> {
        let starknet_os_config = self.starknet_os_config.clone();
        let block_number = BlockNumber(py_attr(block_info, "block_number")?);
        let block_context = BlockContext {
            chain_id: starknet_os_config.chain_id,
            block_number,
            block_timestamp: BlockTimestamp(py_attr(block_info, "block_timestamp")?),
            sequencer_address: ContractAddress::try_from(self.sequencer_address.0)?,
            fee_token_address: ContractAddress::try_from(starknet_os_config.fee_token_address.0)?,
            vm_resource_fee_cost: self.cairo_resource_fee_weights.clone(),
            gas_price: py_attr(block_info, "gas_price")?,
            invoke_tx_max_n_steps: self.invoke_tx_max_n_steps,
            validate_max_n_steps: self.validate_max_n_steps,
            max_recursion_depth,
        };

        Ok(block_context)
    }
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
