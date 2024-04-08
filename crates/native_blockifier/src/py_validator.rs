use blockifier::blockifier::transaction_executor::TransactionExecutor;
use blockifier::context::{BlockContext, TransactionContext};
use blockifier::execution::call_info::CallInfo;
use blockifier::fee::actual_cost::TransactionReceipt;
use blockifier::fee::fee_checks::PostValidationReport;
use blockifier::state::cached_state::{CachedState, GlobalContractCache};
use blockifier::state::state_api::StateReader;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::objects::TransactionInfo;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::versioned_constants::VersionedConstants;
use pyo3::{pyclass, pymethods, PyAny};
use starknet_api::core::Nonce;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::TransactionHash;

use crate::errors::{NativeBlockifierResult, StatefulValidatorResult};
use crate::py_block_executor::{into_block_context_args, PyGeneralConfig};
use crate::py_state_diff::PyBlockInfo;
use crate::py_transaction::{py_account_tx, PyClassInfo};
use crate::py_utils::PyFelt;
use crate::state_readers::py_state_reader::PyStateReader;

#[pyclass]
pub struct PyValidator {
    pub stateful_validator: StatefulValidator<PyStateReader>,
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
        // Create the state.
        let global_contract_cache = GlobalContractCache::new(global_contract_cache_size);
        let state_reader = PyStateReader::new(state_reader_proxy);
        let state = CachedState::new(state_reader, global_contract_cache);

        // Create the block context.
        let (block_info, chain_info) = into_block_context_args(&general_config, &next_block_info)?;
        let versioned_constants = VersionedConstants::latest_constants_with_overrides(
            validate_max_n_steps,
            max_recursion_depth,
        );
        let block_context =
            BlockContext::new_unchecked(&block_info, &chain_info, &versioned_constants);

        // Create the stateful validator.
        let max_nonce_for_validation_skip = Nonce(max_nonce_for_validation_skip.0);
        let stateful_validator =
            StatefulValidator::create(state, block_context, max_nonce_for_validation_skip);

        Ok(Self { stateful_validator })
    }

    // Transaction Execution API.

    #[pyo3(signature = (tx, optional_py_class_info, deploy_account_tx_hash))]
    pub fn perform_validations(
        &mut self,
        tx: &PyAny,
        optional_py_class_info: Option<PyClassInfo>,
        deploy_account_tx_hash: Option<PyFelt>,
    ) -> NativeBlockifierResult<()> {
        let account_tx = py_account_tx(tx, optional_py_class_info)?;
        let deploy_account_tx_hash = deploy_account_tx_hash.map(|hash| TransactionHash(hash.0));
        self.stateful_validator.perform_validations(account_tx, deploy_account_tx_hash)?;

        Ok(())
    }
}

/// Manages state related transaction validations for pre-execution flows.
pub struct StatefulValidator<S: StateReader> {
    tx_executor: TransactionExecutor<S>,
    max_nonce_for_validation_skip: Nonce,
}

impl<S: StateReader> StatefulValidator<S> {
    fn create(
        state: CachedState<S>,
        block_context: BlockContext,
        max_nonce_for_validation_skip: Nonce,
    ) -> Self {
        let tx_executor = TransactionExecutor::new(state, block_context);
        Self { tx_executor, max_nonce_for_validation_skip }
    }

    fn perform_validations(
        &mut self,
        tx: AccountTransaction,
        deploy_account_tx_hash: Option<TransactionHash>,
    ) -> StatefulValidatorResult<()> {
        // Deploy account transactions should be fully executed, since the constructor must run
        // before `__validate_deploy__`. The execution already includes all necessary validations,
        // so they are skipped here.
        if let AccountTransaction::DeployAccount(_) = tx {
            self.execute(tx)?;
            return Ok(());
        }

        // First, we check if the transaction should be skipped due to the deploy account not being
        // processed. It is done before the pre-validations checks because, in these checks, we
        // change the state (more precisely, we increment the nonce).
        let tx_context = self.tx_executor.block_context.to_tx_context(&tx);
        let skip_validate = self.skip_validate_due_to_unprocessed_deploy_account(
            &tx_context.tx_info,
            deploy_account_tx_hash,
        )?;
        self.perform_pre_validation_stage(&tx, &tx_context)?;

        if skip_validate {
            return Ok(());
        }

        // `__validate__` call.
        let versioned_constants = &tx_context.block_context.versioned_constants();
        let (_optional_call_info, actual_cost) =
            self.validate(&tx, versioned_constants.tx_initial_gas())?;

        // Post validations.
        PostValidationReport::verify(&tx_context, &actual_cost)?;

        Ok(())
    }

    fn execute(&mut self, tx: AccountTransaction) -> StatefulValidatorResult<()> {
        self.tx_executor.execute(Transaction::AccountTransaction(tx), true)?;
        Ok(())
    }

    fn perform_pre_validation_stage(
        &mut self,
        tx: &AccountTransaction,
        tx_context: &TransactionContext,
    ) -> StatefulValidatorResult<()> {
        let strict_nonce_check = false;
        // Run pre-validation in charge fee mode to perform fee and balance related checks.
        let charge_fee = true;
        tx.perform_pre_validation_stage(
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
        deploy_account_tx_hash: Option<TransactionHash>,
    ) -> StatefulValidatorResult<bool> {
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
        tx: &AccountTransaction,
        remaining_gas: u64,
    ) -> StatefulValidatorResult<(Option<CallInfo>, TransactionReceipt)> {
        Ok(self.tx_executor.validate(tx, remaining_gas)?)
    }
}
