use blockifier::state::cached_state::GlobalContractCache;
use pyo3::prelude::*;

use crate::errors::NativeBlockifierResult;
use crate::papyrus_state::PapyrusReader;
use crate::py_block_executor::PyGeneralConfig;
use crate::py_state_diff::PyBlockInfo;
use crate::py_transaction_execution_info::{
    PyCallInfo, PyTransactionExecutionInfo, PyVmExecutionResources,
};
use crate::transaction_executor::TransactionExecutor;

/// Manages transaction validation for pre-execution flows.
#[pyclass]
pub struct PyValidator {
    pub general_config: PyGeneralConfig,
    pub max_recursion_depth: usize,
    pub tx_executor: Option<TransactionExecutor<PapyrusReader>>,
    pub global_contract_cache: GlobalContractCache,
}

#[pymethods]
impl PyValidator {
    #[new]
    #[pyo3(signature = (general_config, max_recursion_depth ))]
    pub fn create(general_config: PyGeneralConfig, max_recursion_depth: usize) -> Self {
        log::debug!("Initializing Validator...");
        let tx_executor = None;

        log::debug!("Initialized Validator.");
        Self {
            general_config,
            max_recursion_depth,
            tx_executor,
            global_contract_cache: GlobalContractCache::default(),
        }
    }

    // Transaction Execution API.

    /// Initializes the transaction executor for the given block.
    #[pyo3(signature = (_next_block_info, _state_reader_proxy))]
    fn setup_validation_context(
        &mut self,
        _next_block_info: PyBlockInfo,
        _state_reader_proxy: &PyAny,
    ) -> NativeBlockifierResult<()> {
        // Create a state reader from the state_reader_proxy, use it to create a
        // TransactionExecutor instance, and set it at self.tx_executor.
        unimplemented!();
    }

    fn teardown_validation_context(&mut self) {
        self.tx_executor = None;
    }

    /// Applicable solely to account deployment transactions: the execution of the constructor
    // is required before they can be validated.
    #[pyo3(signature = (tx, raw_contract_class))]
    pub fn execute(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
    ) -> NativeBlockifierResult<(PyTransactionExecutionInfo, PyVmExecutionResources)> {
        let charge_fee = false;
        self.tx_executor().execute(tx, raw_contract_class, charge_fee)
    }

    #[pyo3(signature = (tx, remaining_gas, raw_contract_class))]
    pub fn validate(
        &mut self,
        tx: &PyAny,
        remaining_gas: u64,
        raw_contract_class: Option<&str>,
    ) -> NativeBlockifierResult<Option<PyCallInfo>> {
        let maybe_call_info = self.tx_executor().validate(tx, remaining_gas, raw_contract_class)?;
        Ok(maybe_call_info.map(PyCallInfo::from))
    }

    pub fn close(&mut self) {
        log::debug!("Closing validator.");
        self.teardown_validation_context();
    }

    #[pyo3(signature = (general_config))]
    #[staticmethod]
    fn create_for_testing(general_config: PyGeneralConfig) -> Self {
        Self {
            general_config,
            max_recursion_depth: 50,
            tx_executor: None,
            global_contract_cache: GlobalContractCache::default(),
        }
    }
}

impl PyValidator {
    pub fn tx_executor(&mut self) -> &mut TransactionExecutor<PapyrusReader> {
        self.tx_executor.as_mut().expect("Transaction executor should be initialized")
    }
}
