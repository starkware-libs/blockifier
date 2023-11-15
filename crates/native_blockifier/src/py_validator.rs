use std::collections::HashMap;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::abi::constants::CONSTRUCTOR_ENTRY_POINT_NAME;
use blockifier::fee::actual_cost::{ActualCost, PostExecutionReport};
use blockifier::state::cached_state::GlobalContractCache;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::constants::{
    EXECUTE_ENTRY_POINT_NAME, TRANSFER_ENTRY_POINT_NAME, VALIDATE_DECLARE_ENTRY_POINT_NAME,
    VALIDATE_DEPLOY_ENTRY_POINT_NAME, VALIDATE_ENTRY_POINT_NAME,
};
use blockifier::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};
use blockifier::transaction::transaction_execution::Transaction;
use pyo3::prelude::*;
use starknet_api::hash::StarkFelt;

use crate::errors::{
    NativeBlockifierError, NativeBlockifierResult, NativeBlockifierValidationsError,
};
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
    // #[pyo3(...)] and pass an account transaction instead of PyAny.
    #[pyo3(signature = (tx, remaining_gas, raw_contract_class))]
    pub fn validate(
        &mut self,
        tx: &PyAny,
        remaining_gas: u64,
        raw_contract_class: Option<&str>,
    ) -> NativeBlockifierResult<(Option<PyCallInfo>, PyActualCost)> {
        let tx_type: String = py_enum_name(tx, "tx_type")?;
        let account_tx = py_account_tx(&tx_type, tx, raw_contract_class)?;
        let (optional_call_info, actual_cost) =
            self.tx_executor().validate(&account_tx, remaining_gas)?;
        let py_optional_call_info = optional_call_info.map(PyCallInfo::from);

        Ok((py_optional_call_info, PyActualCost::from(actual_cost)))
    }

    pub fn close(&mut self) {
        log::debug!("Closing validator.");
        self.teardown_validation_context();
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

        // Deploy account transactions should be fully executed (including pre-validation and
        // post-execution), since the constructor is ran before validation.
        if let AccountTransaction::DeployAccount(_deploy_account_tx) = account_tx {
            let (py_tx_execution_info, _py_casm_hash_calculation_resources) =
                self.execute(tx, raw_contract_class)?;
            self.check_call_succeeded(py_tx_execution_info.execute_call_info)?;
            self.check_call_succeeded(py_tx_execution_info.validate_call_info)?;
            return Ok(());
        }
        let account_tx_context = account_tx.get_account_tx_context();

        // Other (not deploy account) transactions should be validated only (with pre-validation
        // before, and post-validation after).
        let tx_executor = self.tx_executor();
        let strict_nonce_check = false;
        // Run pre-validation in charge fee mode to perform fee and balance related checks.
        let charge_fee = true;
        account_tx.perform_pre_validation_stage(
            &mut tx_executor.state,
            &account_tx.get_account_tx_context(),
            &tx_executor.block_context,
            charge_fee,
            strict_nonce_check,
        )?;

        // `__validate__` call.
        let (_py_optional_call_info, py_actual_cost) =
            self.validate(tx, Transaction::initial_gas(), raw_contract_class)?;

        // Post validations.
        if !account_tx.get_account_tx_context().is_v0() {
            self.check_call_succeeded(_py_optional_call_info)?;
        }

        self.perform_post_validation_stage(&account_tx_context, &ActualCost::from(py_actual_cost))?;

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

    fn perform_post_validation_stage(
        &mut self,
        account_tx_context: &AccountTransactionContext,
        actual_cost: &ActualCost,
    ) -> TransactionExecutionResult<()> {
        // TODO(Noa, 09/11/2023): Add this logic to `PostValdateReport`.
        if !account_tx_context.enforce_fee()? {
            return Ok(());
        }

        let resource_bounds_report = PostExecutionReport::check_actual_cost_within_bounds(
            &self.tx_executor().block_context,
            actual_cost,
            account_tx_context,
        )?;
        match resource_bounds_report.error() {
            Some(error) => Err(error)?,
            // Note: the balance cannot be changed in `__validate__` (which cannot call other
            // contracts), so there is no need to recheck that balance >= actual_cost.
            None => Ok(()),
        }
    }

    pub fn check_call_succeeded(
        &mut self,
        py_optional_call_info: Option<PyCallInfo>,
    ) -> NativeBlockifierResult<()> {
        let py_call_info = py_optional_call_info.expect("Call info must be not None.");
        if py_call_info.failure_flag.0 != StarkFelt::ZERO {
            return Err(NativeBlockifierError::NativeBlockifierValidationsError(
                NativeBlockifierValidationsError::ValidationError {
                    entry_point_name: selector_to_name(py_call_info.entry_point_selector.0),
                    error_data: py_call_info.retdata.iter().map(|v| v.0).collect(),
                },
            ));
        }
        Ok(())
    }
}

fn selector_to_name(entry_point_selector: StarkFelt) -> String {
    let selector_to_name_map = HashMap::from([
        (selector_from_name(CONSTRUCTOR_ENTRY_POINT_NAME).0, CONSTRUCTOR_ENTRY_POINT_NAME),
        (selector_from_name(EXECUTE_ENTRY_POINT_NAME).0, EXECUTE_ENTRY_POINT_NAME),
        (selector_from_name(TRANSFER_ENTRY_POINT_NAME).0, TRANSFER_ENTRY_POINT_NAME),
        (selector_from_name(VALIDATE_ENTRY_POINT_NAME).0, VALIDATE_ENTRY_POINT_NAME),
        (
            selector_from_name(VALIDATE_DECLARE_ENTRY_POINT_NAME).0,
            VALIDATE_DECLARE_ENTRY_POINT_NAME,
        ),
        (selector_from_name(VALIDATE_DEPLOY_ENTRY_POINT_NAME).0, VALIDATE_DEPLOY_ENTRY_POINT_NAME),
    ]);

    selector_to_name_map
        .get(&entry_point_selector)
        .unwrap_or_else(|| panic!("{} is not defined.", entry_point_selector))
        .to_string()
}
