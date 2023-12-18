use blockifier::execution::call_info::{check_call_succeeded, CallInfo};
use blockifier::fee::actual_cost::ActualCost;
use blockifier::fee::fee_checks::PostValidationReport;
use blockifier::state::cached_state::GlobalContractCache;
use blockifier::state::state_api::StateReader;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};
use blockifier::transaction::transaction_execution::Transaction;
use pyo3::prelude::*;
use starknet_api::core::Nonce;
use starknet_api::hash::StarkFelt;

use crate::errors::NativeBlockifierResult;
use crate::py_block_executor::PyGeneralConfig;
use crate::py_state_diff::PyBlockInfo;
use crate::py_transaction::py_account_tx;
use crate::py_transaction_execution_info::{PyTransactionExecutionInfo, PyVmExecutionResources};
use crate::py_utils::PyFelt;
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
        let account_tx = py_account_tx(tx, raw_contract_class)?;
        let account_tx_context = account_tx.get_account_tx_context();
        // Deploy account transactions should be fully executed, since the constructor must run
        // before `__validate_deploy__`. The execution already includes all necessary validations,
        // so they are skipped here.
        if let AccountTransaction::DeployAccount(_deploy_account_tx) = account_tx {
            let (_py_tx_execution_info, _py_casm_hash_calculation_resources) =
                self.execute(tx, raw_contract_class)?;
            return Ok(());
        }

        // First, we check if the transaction should be skipped due to the deploy account not being
        // processed. It is done before the pre-validations checks because, in these checks, we
        // change the state (more precisely, we increment the nonce).
        let skip_validate = self.skip_validate_due_to_unprocessed_deploy_account(
            &account_tx_context,
            deploy_account_tx_hash,
        )?;
        self.perform_pre_validation_stage(&account_tx)?;

        if skip_validate {
            return Ok(());
        }

        // `__validate__` call.
        let (_optional_call_info, actual_cost) =
            self.validate(account_tx, Transaction::initial_gas())?;

        // Post validations.
        let _ = check_call_succeeded(&_optional_call_info);
        self.perform_post_validation_stage(&account_tx_context, &actual_cost)?;

        Ok(())
    }

    #[cfg(any(feature = "testing", test))]
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

    /// Applicable solely to account deployment transactions: the execution of the constructor
    /// is required before they can be validated.
    fn execute(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
    ) -> NativeBlockifierResult<(PyTransactionExecutionInfo, PyVmExecutionResources)> {
        let limit_execution_steps_by_resource_bounds = true;
        self.tx_executor().execute(tx, raw_contract_class, limit_execution_steps_by_resource_bounds)
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

    fn validate(
        &mut self,
        account_tx: AccountTransaction,
        remaining_gas: u64,
    ) -> NativeBlockifierResult<(Option<CallInfo>, ActualCost)> {
        let (optional_call_info, actual_cost) =
            self.tx_executor().validate(&account_tx, remaining_gas)?;

        Ok((optional_call_info, actual_cost))
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
}
