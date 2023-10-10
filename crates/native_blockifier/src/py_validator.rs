use blockifier::state::cached_state::GlobalContractCache;
use pyo3::prelude::*;

use crate::errors::NativeBlockifierResult;
use crate::py_block_executor::PyGeneralConfig;
use crate::py_state_diff::PyBlockInfo;
use crate::py_transaction_execution_info::{
    PyCallInfo, PyTransactionExecutionInfo, PyVmExecutionResources,
};
use crate::state_readers::papyrus_state::PapyrusReader;
use crate::transaction_executor::TransactionExecutor;

#[pyclass]
/// Manages transaction validation for pre-execution flows.
pub struct PyValidator {
    pub general_config: PyGeneralConfig,
    pub max_recursion_depth: usize,
    // TODO: Once we decide on which state reader to use, replaced PapyrusReader below with that.
    // Currently using PapyrusReader to appease the type checker and since pyclass doesn't support
    // generics.
    pub tx_executor: Option<TransactionExecutor<PapyrusReader>>,
    pub global_contract_cache: GlobalContractCache,
}

#[pymethods]
impl PyValidator {
    #[new]
    #[pyo3(signature = (general_config, max_recursion_depth))]
    pub fn create(general_config: PyGeneralConfig, max_recursion_depth: usize) -> Self {
        log::debug!("Initializing Block Executor...");
        let tx_executor = None;

        log::debug!("Initialized Block Executor.");
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
        unimplemented!(
            "Once we decide on a state reader, initialize it here and initialize the transaction \
             executor with it."
        )
    }

    fn teardown_validation_context(&mut self) {
        self.tx_executor = None;
    }

    #[pyo3(signature = (tx, raw_contract_class))]
    /// Applicable solely to account deployment transactions: the execution of the constructor
    // is required before they can be validated.
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
    // TODO: replace PapyrusReader with PyStateReader once it's in.
    pub fn tx_executor(&mut self) -> &mut TransactionExecutor<PapyrusReader> {
        self.tx_executor.as_mut().expect("Transaction executor should be initialized")
    }
}
