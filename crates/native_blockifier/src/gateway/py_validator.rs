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

#[cfg(test)]
#[path = "py_validator_test.rs"]
mod py_validator_test;

#[pyclass]
/// Manages transaction validation for pre-execution flows, often used in gateway services.
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
    #[pyo3(signature = (general_config, max_recursion_depth ))]
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
        #[pyo3(from_py_with = "handle_negative_block_number")] _next_block_info: PyBlockInfo,
        _state_reader_proxy: &PyAny,
    ) -> NativeBlockifierResult<()> {
        unimplemented!(
            "Once we decide on a state reader, initialize it here and initialize the transaction \
             executor with it."
        )
        // let reader = ToBeDecoded::new(state_reader_proxy);

        // let tx_executor = TransactionExecutor::new(
        //     reader,
        //     &self.general_config,
        //     next_block_info,
        //     self.max_recursion_depth,
        //     self.global_contract_cache.clone(),
        // )?;
        // self.tx_executor = Some(tx_executor);

        // Ok(())
    }

    fn teardown_validation_context(&mut self) {
        self.tx_executor = None;
    }

    #[pyo3(signature = (tx, raw_contract_class))]
    /// Applicable solely to `deploy account` transactions. These transaction's constructor
    /// generally requires execution of the constructor before they can be validated. For all other
    /// transaction types, execution is not a prerequisite for validation.
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
    // TODO replace PapyrusReader with PyStateReader once it's in.
    pub fn tx_executor(&mut self) -> &mut TransactionExecutor<PapyrusReader> {
        self.tx_executor.as_mut().expect("Transaction executor should be initialized")
    }
}

// Typing edge case where python genesis block has block number -1.
pub fn handle_negative_block_number(block_info: &PyAny) -> PyResult<PyBlockInfo> {
    let block_number: i64 = block_info.getattr("block_number")?.extract()?;
    assert!(-1 <= block_number);

    let block_number = u64::try_from(block_number).unwrap_or(0_u64);

    Ok(PyBlockInfo {
        block_number,
        block_timestamp: block_info.getattr("block_timestamp")?.extract()?,
        sequencer_address: block_info.getattr("sequencer_address")?.extract()?,
        eth_l1_gas_price: block_info.getattr("eth_l1_gas_price")?.extract()?,
        strk_l1_gas_price: block_info.getattr("str_l1_gas_price")?.extract()?,
    })
}
