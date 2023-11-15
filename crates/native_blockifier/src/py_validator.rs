use std::collections::HashMap;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::abi::constants::CONSTRUCTOR_ENTRY_POINT_NAME;
use blockifier::fee::actual_cost::ActualCost;
use blockifier::fee::fee_checks::PostValidationReport;
use blockifier::state::cached_state::GlobalContractCache;
use blockifier::state::state_api::StateReader;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::constants::{
    EXECUTE_ENTRY_POINT_NAME, TRANSFER_ENTRY_POINT_NAME, VALIDATE_DECLARE_ENTRY_POINT_NAME,
    VALIDATE_DEPLOY_ENTRY_POINT_NAME, VALIDATE_ENTRY_POINT_NAME,
};
use blockifier::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};
use blockifier::transaction::transaction_execution::Transaction;
use pyo3::prelude::*;
use starknet_api::core::Nonce;
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
    pub max_nonce_for_validation_skip: Nonce,
    pub tx_executor: Option<TransactionExecutor<PyStateReader>>,
    pub global_contract_cache: GlobalContractCache,
}

#[pymethods]
impl PyValidator {
    #[new]
    #[pyo3(signature = (general_config, max_recursion_depth, max_nonce_for_validation_skip))]
    pub fn create(
        general_config: PyGeneralConfig,
        max_recursion_depth: usize,
        max_nonce_for_validation_skip: PyFelt,
    ) -> Self {
        let tx_executor = None;
        let validator = Self {
            general_config,
            max_recursion_depth,
            max_nonce_for_validation_skip: Nonce(max_nonce_for_validation_skip.0),
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

    #[pyo3(signature = (tx, raw_contract_class, deploy_account_tx_hash))]
    pub fn perform_validations(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
        deploy_account_tx_hash: Option<PyFelt>,
    ) -> NativeBlockifierResult<()> {
        let tx_type: String = py_enum_name(tx, "tx_type")?;
        let account_tx = py_account_tx(&tx_type, tx, raw_contract_class)?;
        let account_tx_context = account_tx.get_account_tx_context();
        // Deploy account transactions should be fully executed, since the constructor must run
        // before `__validate_deploy__`. The execution already includes all necessary validations,
        // so they are skipped here.
        if let AccountTransaction::DeployAccount(_deploy_account_tx) = account_tx {
            let (py_tx_execution_info, _py_casm_hash_calculation_resources) =
                self.execute(tx, raw_contract_class)?;
            self.check_call_succeeded(py_tx_execution_info.execute_call_info)?;
            self.check_call_succeeded(py_tx_execution_info.validate_call_info)?;
            return Ok(());
        }

        self.perform_pre_validation_stage(&account_tx)?;

        if self.skip_validate_due_to_unprocessed_deploy_account(
            &account_tx_context,
            deploy_account_tx_hash,
        )? {
            return Ok(());
        }

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
            max_nonce_for_validation_skip: Nonce(StarkFelt::ONE),
            tx_executor: None,
            global_contract_cache: GlobalContractCache::default(),
        }
    }
}

impl PyValidator {
    fn tx_executor(&mut self) -> &mut TransactionExecutor<PyStateReader> {
        self.tx_executor.as_mut().expect("Transaction executor should be initialized")
    }

    fn perform_pre_validation_stage(
        &mut self,
        account_tx: &AccountTransaction,
    ) -> NativeBlockifierResult<()> {
        let account_tx_context = account_tx.get_account_tx_context();

        let tx_executor = self.tx_executor();
        let strict_nonce_check = false;
        // Run pre-validation in charge fee mode to perform fee and balance related checks.
        let charge_fee = true;
        account_tx.perform_pre_validation_stage(
            &mut tx_executor.state,
            &account_tx_context,
            &tx_executor.block_context,
            charge_fee,
            strict_nonce_check,
        )?;

        Ok(())
    }

    // Check if deploy account was submitted but not processed yet. If so, then skip
    // `__validate__` method for subsequent transactions for a better user experience.
    // (they will otherwise fail solely because the deploy account hasn't been processed yet).
    fn skip_validate_due_to_unprocessed_deploy_account(
        &mut self,
        account_tx_context: &AccountTransactionContext,
        deploy_account_tx_hash: Option<PyFelt>,
    ) -> NativeBlockifierResult<bool> {
        let nonce = self.tx_executor().state.get_nonce_at(account_tx_context.sender_address())?;
        let tx_nonce = account_tx_context.nonce();

        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(StarkFelt::ZERO);
        let is_post_deploy_nonce = Nonce(StarkFelt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;

        Ok(skip_validate)
    }

    fn perform_post_validation_stage(
        &mut self,
        account_tx_context: &AccountTransactionContext,
        actual_cost: &ActualCost,
    ) -> TransactionExecutionResult<()> {
        PostValidationReport::verify(
            &self.tx_executor().block_context,
            account_tx_context,
            actual_cost,
        )
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
