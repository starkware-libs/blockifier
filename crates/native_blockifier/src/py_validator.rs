use blockifier::fee::actual_cost::{ActualCost, PostExecutionAuditor};
use blockifier::state::cached_state::GlobalContractCache;
use blockifier::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};
use blockifier::transaction::transaction_execution::Transaction;
use pyo3::prelude::*;

use crate::errors::NativeBlockifierResult;
use crate::py_block_executor::PyGeneralConfig;
use crate::py_state_diff::PyBlockInfo;
use crate::py_transaction::{py_tx, PyActualCost};
use crate::py_transaction_execution_info::{
    PyCallInfo, PyTransactionExecutionInfo, PyVmExecutionResources,
};
use crate::py_utils::py_enum_name;
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
    #[pyo3(signature = (tx, raw_contract_class))]
    pub fn execute(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
    ) -> NativeBlockifierResult<(PyTransactionExecutionInfo, PyVmExecutionResources)> {
        let limit_execution_steps_by_resource_bounds = true;
        self.tx_executor().execute(tx, raw_contract_class, limit_execution_steps_by_resource_bounds)
    }

    // TODO(Noa, 20/11/23): when this method is no longer exrernalize to python, remove
    // #[pyo3(...)].
    #[pyo3(signature = (tx, remaining_gas, raw_contract_class))]
    pub fn validate(
        &mut self,
        tx: &PyAny,
        remaining_gas: u64,
        raw_contract_class: Option<&str>,
    ) -> NativeBlockifierResult<(Option<PyCallInfo>, PyActualCost)> {
        let tx_type: String = py_enum_name(tx, "tx_type")?;
        let Transaction::AccountTransaction(account_tx) = py_tx(&tx_type, tx, raw_contract_class)?
        else {
            panic!("L1 handlers should not be validated separately, only as part of execution")
        };
        let (optional_call_info, actual_cost) =
            self.tx_executor().validate(&account_tx, remaining_gas)?;
        let py_optional_call_info = optional_call_info.map(PyCallInfo::from);

        Ok((py_optional_call_info, PyActualCost::from(actual_cost)))
    }

    pub fn close(&mut self) {
        log::debug!("Closing validator.");
        self.teardown_validation_context();
    }

    #[pyo3(signature = (tx, raw_contract_class))]
    pub fn perform_validations(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
    ) -> NativeBlockifierResult<Option<PyCallInfo>> {
        let tx_type: String = py_enum_name(tx, "tx_type")?;
        let Transaction::AccountTransaction(account_tx) = py_tx(&tx_type, tx, raw_contract_class)?
        else {
            panic!("L1 handlers should not be validated separately, only as part of execution")
        };
        let account_tx_context = account_tx.get_account_tx_context();
        // Pre validations.
        // TODO(Amos, 09/11/2023): Add pre-validation checks.

        // `__validate__` call.
        let (py_optional_call_info, py_actual_cost) =
            self.validate(tx, Transaction::initial_gas(), raw_contract_class)?;

        // Post validations.
        // TODO(Noa, 09/11/2023): Add post-validation checks.
        self.post_validate(&account_tx_context, &ActualCost::from(py_actual_cost))?;

        Ok(py_optional_call_info)
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

    fn post_validate(
        &mut self,
        account_tx_context: &AccountTransactionContext,
        actual_cost: &ActualCost,
    ) -> TransactionExecutionResult<()> {
        // Post validations.
        let charge_fee = true;
        let auditor = PostExecutionAuditor::new(
            &self.tx_executor().block_context,
            account_tx_context,
            actual_cost,
            charge_fee,
        )?;

        // Note- The balance cannot be changed in `__validate__`, so there is no need to recheck
        // that balance >= actual_cost.
        auditor.verify_valid_actual_cost()
    }
}
