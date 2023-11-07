use blockifier::state::cached_state::GlobalContractCache;
use blockifier::state::state_api::StateReader;
use blockifier::transaction::transaction_execution::Transaction;
use pyo3::prelude::*;
use starknet_api::core::Nonce;
use starknet_api::hash::StarkFelt;

use crate::errors::NativeBlockifierResult;
use crate::py_block_executor::PyGeneralConfig;
use crate::py_state_diff::PyBlockInfo;
use crate::py_transaction::{py_tx, PyActualCost};
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

    #[pyo3(signature = (tx, remaining_gas, raw_contract_class, deploy_account_tx_hash))]
    pub fn perform_validations(
        &mut self,
        tx: &PyAny,
        remaining_gas: u64,
        raw_contract_class: Option<&str>,
        deploy_account_tx_hash: Option<PyFelt>,
    ) -> NativeBlockifierResult<Option<PyCallInfo>> {
        if !self.pre_validation_checks(tx, raw_contract_class, deploy_account_tx_hash)? {
            // Pre validations have failed or validation should be skipped.
            return Ok(None);
        }

        // `__validate__` call.
        let (py_optional_call_info, _actual_cost) =
            self.validate(tx, remaining_gas, raw_contract_class)?;

        // Post validations.
        // TODO(Noa, 09/11/2023): Add post-validation checks.

        Ok(py_optional_call_info)
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

    // All checks that should be done before running __validate__.
    // Returns true if and only if the pre validation checks succeeded.
    fn pre_validation_checks(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
        deploy_account_tx_hash: Option<PyFelt>,
    ) -> NativeBlockifierResult<bool> {
        self.should_do_validations(tx, raw_contract_class, deploy_account_tx_hash)
    }

    fn should_do_validations(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
        deploy_account_tx_hash: Option<PyFelt>,
    ) -> NativeBlockifierResult<bool> {
        let tx_type: String = py_enum_name(tx, "tx_type")?;
        let Transaction::AccountTransaction(account_tx) = py_tx(&tx_type, tx, raw_contract_class)?
        else {
            panic!("L1 handlers should not be validated separately, only as part of execution")
        };

        let account_tx_context = account_tx.get_account_tx_context();
        let nonce = self.tx_executor().state.get_nonce_at(account_tx_context.sender_address())?;
        let tx_nonce = account_tx_context.nonce();

        // Check if deploy account was submitted but not processed yet. If so, then skip
        // validations for subsequent transactions for a better user experience.
        // (Otherwise they'll fail solely because the deploy account hasn't been processed yet.)

        let deploy_account_not_processed = nonce == Nonce(StarkFelt::ZERO);
        let is_post_deploy_nonce = Nonce(StarkFelt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;
        let deploy_account_has_been_sent = deploy_account_tx_hash.is_some();

        let skip_validations = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip
            && deploy_account_has_been_sent;

        Ok(skip_validations)
    }
}
