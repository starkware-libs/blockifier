use blockifier::state::cached_state::GlobalContractCache;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::transaction_execution::Transaction;
use pyo3::prelude::*;
use starknet_api::hash::StarkFelt;

use crate::errors::{self, NativeBlockifierResult, NativeBlockifierValidationsError};
use crate::py_block_executor::PyGeneralConfig;
use crate::py_state_diff::PyBlockInfo;
use crate::py_transaction::{py_account_tx, PyActualCost};
use crate::py_transaction_execution_info::{
    PyCallInfo, PyTransactionExecutionInfo, PyVmExecutionResources,
};
use crate::py_utils::{py_enum_name, PyFelt};
use crate::state_readers::py_state_reader::PyStateReader;
use crate::transaction_executor::TransactionExecutor;

/// Manages transaction validation for pre-execution flows.
#[pyclass]
pub struct PyValidator {
    pub general_config: PyGeneralConfig,
    pub max_recursion_depth: usize,
    pub tx_executor: Option<TransactionExecutor<PyStateReader>>,
    pub global_contract_cache: GlobalContractCache,
}

#[pymethods]
impl PyValidator {
    #[new]
    #[pyo3(signature = (general_config, max_recursion_depth))]
    pub fn create(general_config: PyGeneralConfig, max_recursion_depth: usize) -> Self {
        let tx_executor = None;
        let validator = Self {
            general_config,
            max_recursion_depth,
            tx_executor,
            global_contract_cache: GlobalContractCache::default(),
        };
        log::debug!("Initialized Validator.");

        validator
    }

    // Transaction Execution API.

    /// Initializes the transaction executor for the given block.
    #[pyo3(signature = (next_block_info, state_reader_proxy))]
    fn setup_validation_context(
        &mut self,
        next_block_info: PyBlockInfo,
        state_reader_proxy: &PyAny,
    ) -> NativeBlockifierResult<()> {
        let reader = PyStateReader::new(state_reader_proxy);

        assert!(
            self.tx_executor.is_none(),
            "Transaction executor should be torn down between calls to validate"
        );
        self.tx_executor = Some(TransactionExecutor::new(
            reader,
            &self.general_config,
            next_block_info,
            self.max_recursion_depth,
            self.global_contract_cache.clone(),
        )?);

        Ok(())
    }

    fn teardown_validation_context(&mut self) {
        self.tx_executor = None;
    }

    /// Applicable solely to account deployment transactions: the execution of the constructor
    // is required before they can be validated.
    // TODO(Noa, 20/11/23): when this method is no longer externalized to python, remove
    // #[pyo3(...)].
    #[pyo3(signature = (tx, raw_contract_class))]
    pub fn execute(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
    ) -> NativeBlockifierResult<(PyTransactionExecutionInfo, PyVmExecutionResources)> {
        let limit_execution_steps_by_resource_bounds = true;
        self.tx_executor().execute(tx, raw_contract_class, limit_execution_steps_by_resource_bounds)
    }

    // TODO(Noa, 20/11/23): when this method is no longer externalized to python, remove
    // #[pyo3(...)].
    #[pyo3(signature = (tx, remaining_gas, raw_contract_class))]
    pub fn validate(
        &mut self,
        tx: &PyAny,
        remaining_gas: u64,
        raw_contract_class: Option<&str>,
    ) -> NativeBlockifierResult<(Option<PyCallInfo>, PyActualCost)> {
        let (optional_call_info, actual_cost) =
            self.tx_executor().validate(tx, remaining_gas, raw_contract_class)?;
        let py_optional_call_info = optional_call_info.map(PyCallInfo::from);

        Ok((py_optional_call_info, PyActualCost::from(actual_cost)))
    }

    pub fn close(&mut self) {
        log::debug!("Closing validator.");
        self.teardown_validation_context();
    }

    pub fn check_call_succeeded(
        &mut self,
        py_optional_call_info: Option<PyCallInfo>,
    ) -> NativeBlockifierResult<()> {
        let py_call_info = py_optional_call_info.expect("Call info must be not None.");
        if py_call_info.failure_flag.0 != StarkFelt::ZERO {
            return Err(errors::NativeBlockifierError::NativeBlockifierValidateError(
                NativeBlockifierValidationsError::ValidationError {
                    entry_point_name: py_call_info.entry_point_selector.0.to_string(),
                    error_data: py_call_info.retdata.iter().map(|v| v.0).collect(),
                },
            ));
        }
        Ok(())
    }

    #[pyo3(signature = (tx, raw_contract_class, _deploy_account_tx_hash))]
    pub fn perform_validations(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
        _deploy_account_tx_hash: Option<PyFelt>,
    ) -> NativeBlockifierResult<()> {
        let tx_type: String = py_enum_name(tx, "tx_type")?;
        let account_tx = py_account_tx(&tx_type, tx, raw_contract_class)?;
        if let AccountTransaction::DeployAccount(_deploy_account_tx) = account_tx {
            let (_py_tx_execution_info, _py_casm_hash_calculation_resources) =
                self.execute(tx, raw_contract_class)?;
            self.check_call_succeeded(_py_tx_execution_info.validate_call_info)?;
            self.check_call_succeeded(_py_tx_execution_info.execute_call_info)?;
            return Ok(());
        }

        // Pre validations.
        // TODO(Amos, 09/11/2023): Add pre-validation checks.
        let tx_type: String = py_enum_name(tx, "tx_type")?;
        let account_tx = py_account_tx(&tx_type, tx, raw_contract_class)?;

        // `__validate__` call.
        let (py_optional_validate_call_info, _actual_cost) =
            self.validate(tx, Transaction::initial_gas(), raw_contract_class)?;

        // Post validations.
        // TODO(Noa, 09/11/2023): Add post-validation checks.
        if !account_tx.get_account_tx_context().is_v0() {
            self.check_call_succeeded(py_optional_validate_call_info)?;
        }
        Ok(())
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
    pub fn tx_executor(&mut self) -> &mut TransactionExecutor<PyStateReader> {
        self.tx_executor.as_mut().expect("Transaction executor should be initialized")
    }
}
