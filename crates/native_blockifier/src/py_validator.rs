use blockifier::context::{BlockContext, TransactionContext};
use blockifier::execution::call_info::CallInfo;
use blockifier::fee::actual_cost::ActualCost;
use blockifier::fee::fee_checks::PostValidationReport;
use blockifier::state::cached_state::{
    CachedState, GlobalContractCache, GLOBAL_CONTRACT_CACHE_SIZE_FOR_TEST,
};
use blockifier::state::state_api::StateReader;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::objects::{
    TransactionExecutionInfo, TransactionExecutionResult, TransactionInfo,
};
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::versioned_constants::VersionedConstants;
use pyo3::prelude::*;
use starknet_api::core::Nonce;
use starknet_api::hash::StarkFelt;

use crate::errors::NativeBlockifierResult;
use crate::py_block_executor::{into_block_context_args, PyGeneralConfig};
use crate::py_state_diff::PyBlockInfo;
use crate::py_transaction::{py_account_tx, py_tx};
use crate::py_transaction_execution_info::PyBouncerInfo;
use crate::py_utils::{versioned_constants_with_overrides, PyFelt};
use crate::state_readers::py_state_reader::PyStateReader;
use crate::transaction_executor::TransactionExecutor;

/// Manages transaction validation for pre-execution flows.
#[pyclass]
pub struct PyValidator {
    pub max_nonce_for_validation_skip: Nonce,
    pub tx_executor: TransactionExecutor<PyStateReader>,
}

#[pymethods]
impl PyValidator {
    #[new]
    #[pyo3(signature = (general_config, state_reader_proxy, next_block_info, validate_max_n_steps, max_recursion_depth, global_contract_cache_size, max_nonce_for_validation_skip))]
    pub fn create(
        general_config: PyGeneralConfig,
        state_reader_proxy: &PyAny,
        next_block_info: PyBlockInfo,
        validate_max_n_steps: u32,
        max_recursion_depth: usize,
        global_contract_cache_size: usize,
        max_nonce_for_validation_skip: PyFelt,
    ) -> NativeBlockifierResult<Self> {
        let versioned_constants =
            versioned_constants_with_overrides(validate_max_n_steps, max_recursion_depth);
        let global_contract_cache = GlobalContractCache::new(global_contract_cache_size);
        let state_reader = PyStateReader::new(state_reader_proxy);
        let state = CachedState::new(state_reader, global_contract_cache);

        let (block_info, chain_info) = into_block_context_args(&general_config, &next_block_info)?;
        // TODO(Yael 24/01/24): calc block_context using pre_process_block
        let block_context =
            BlockContext::new_unchecked(&block_info, &chain_info, &versioned_constants);
        let tx_executor = TransactionExecutor::new(state, block_context)?;

        let validator = Self {
            max_nonce_for_validation_skip: Nonce(max_nonce_for_validation_skip.0),
            tx_executor,
        };

        Ok(validator)
    }

    // Transaction Execution API.

    #[pyo3(signature = (tx, raw_contract_class, deploy_account_tx_hash))]
    pub fn perform_validations(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
        deploy_account_tx_hash: Option<PyFelt>,
    ) -> NativeBlockifierResult<()> {
        let account_tx = py_account_tx(tx, raw_contract_class)?;
        let tx_context = self.tx_executor.block_context.to_tx_context(&account_tx);
        // Deploy account transactions should be fully executed, since the constructor must run
        // before `__validate_deploy__`. The execution already includes all necessary validations,
        // so they are skipped here.
        if let AccountTransaction::DeployAccount(_deploy_account_tx) = account_tx {
            let (_tx_execution_info, _py_bouncer_info) = self.execute(tx, raw_contract_class)?;
            // TODO(Ayelet, 09/11/2023): Check call succeeded.

            return Ok(());
        }

        // First, we check if the transaction should be skipped due to the deploy account not being
        // processed. It is done before the pre-validations checks because, in these checks, we
        // change the state (more precisely, we increment the nonce).
        let skip_validate = self.skip_validate_due_to_unprocessed_deploy_account(
            &tx_context.tx_info,
            deploy_account_tx_hash,
        )?;
        self.perform_pre_validation_stage(&account_tx, &tx_context)?;

        if skip_validate {
            return Ok(());
        }

        // `__validate__` call.
        let versioned_constants = &tx_context.block_context.versioned_constants();
        let (_optional_call_info, actual_cost) =
            self.validate(account_tx, versioned_constants.tx_initial_gas())?;

        // Post validations.
        // TODO(Ayelet, 09/11/2023): Check call succeeded.
        self.perform_post_validation_stage(&tx_context, &actual_cost)?;

        Ok(())
    }

    #[cfg(any(feature = "testing", test))]
    #[pyo3(signature = (general_config, state_reader_proxy, next_block_info))]
    #[staticmethod]
    fn create_for_testing(
        general_config: PyGeneralConfig,
        state_reader_proxy: &PyAny,
        next_block_info: PyBlockInfo,
    ) -> NativeBlockifierResult<Self> {
        let state_reader = PyStateReader::new(state_reader_proxy);
        let global_contract_cache = GlobalContractCache::new(GLOBAL_CONTRACT_CACHE_SIZE_FOR_TEST);
        let state = CachedState::new(state_reader, global_contract_cache);

        let (block_info, chain_info) = into_block_context_args(&general_config, &next_block_info)?;
        let block_context = BlockContext::new_unchecked(
            &block_info,
            &chain_info,
            VersionedConstants::latest_constants(),
        );
        // TODO(Yael 24/01/24): calc block_context using pre_process_block
        let tx_executor = TransactionExecutor::new(state, block_context)?;

        Ok(Self { max_nonce_for_validation_skip: Nonce(StarkFelt::ONE), tx_executor })
    }
}

impl PyValidator {
    /// Applicable solely to account deployment transactions: the execution of the constructor
    /// is required before they can be validated.
    fn execute(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
    ) -> NativeBlockifierResult<(TransactionExecutionInfo, PyBouncerInfo)> {
        let limit_execution_steps_by_resource_bounds = true;
        let tx: Transaction = py_tx(tx, raw_contract_class)?;
        self.tx_executor.execute(tx, limit_execution_steps_by_resource_bounds)
    }

    fn perform_pre_validation_stage(
        &mut self,
        account_tx: &AccountTransaction,
        tx_context: &TransactionContext,
    ) -> NativeBlockifierResult<()> {
        let strict_nonce_check = false;
        // Run pre-validation in charge fee mode to perform fee and balance related checks.
        let charge_fee = true;
        account_tx.perform_pre_validation_stage(
            &mut self.tx_executor.state,
            tx_context,
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
        tx_info: &TransactionInfo,
        deploy_account_tx_hash: Option<PyFelt>,
    ) -> NativeBlockifierResult<bool> {
        let nonce = self.tx_executor.state.get_nonce_at(tx_info.sender_address())?;
        let tx_nonce = tx_info.nonce();

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
            self.tx_executor.validate(&account_tx, remaining_gas)?;

        Ok((optional_call_info, actual_cost))
    }

    fn perform_post_validation_stage(
        &mut self,
        tx_context: &TransactionContext,
        actual_cost: &ActualCost,
    ) -> TransactionExecutionResult<()> {
        PostValidationReport::verify(tx_context, actual_cost)
    }
}
