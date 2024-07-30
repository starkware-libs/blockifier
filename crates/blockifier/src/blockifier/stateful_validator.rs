use std::sync::Arc;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use starknet_api::core::{ContractAddress, Nonce};
use thiserror::Error;

use crate::blockifier::config::TransactionExecutorConfig;
use crate::blockifier::transaction_executor::{
    TransactionExecutor, TransactionExecutorError, BLOCK_STATE_ACCESS_ERR,
};
use crate::context::{BlockContext, TransactionContext};
use crate::execution::call_info::CallInfo;
use crate::fee::actual_cost::TransactionReceipt;
use crate::fee::fee_checks::PostValidationReport;
use crate::state::cached_state::CachedState;
use crate::state::errors::StateError;
use crate::state::state_api::StateReader;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::errors::{TransactionExecutionError, TransactionPreValidationError};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::ValidatableTransaction;

#[cfg(test)]
#[path = "stateful_validator_test.rs"]
pub mod stateful_validator_test;

#[derive(Debug, Error)]
pub enum StatefulValidatorError {
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error(transparent)]
    TransactionExecutionError(#[from] TransactionExecutionError),
    #[error(transparent)]
    TransactionExecutorError(#[from] TransactionExecutorError),
    #[error(transparent)]
    TransactionPreValidationError(#[from] TransactionPreValidationError),
}

pub type StatefulValidatorResult<T> = Result<T, StatefulValidatorError>;

/// Manages state related transaction validations for pre-execution flows.
pub struct StatefulValidator<S: StateReader> {
    tx_executor: TransactionExecutor<S>,
}

impl<S: StateReader> StatefulValidator<S> {
    pub fn create(state: CachedState<S>, block_context: BlockContext) -> Self {
        let tx_executor =
            TransactionExecutor::new(state, block_context, TransactionExecutorConfig::default());
        Self { tx_executor }
    }

    pub fn perform_validations(
        &mut self,
        tx: AccountTransaction,
        skip_validate: bool,
    ) -> StatefulValidatorResult<()> {
        // Deploy account transactions should be fully executed, since the constructor must run
        // before `__validate_deploy__`. The execution already includes all necessary validations,
        // so they are skipped here.
        if let AccountTransaction::DeployAccount(_) = tx {
            self.execute(tx)?;
            return Ok(());
        }

        let tx_context = self.tx_executor.block_context.to_tx_context(&tx);
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
        self.tx_executor.execute(&Transaction::AccountTransaction(tx))?;
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
            self.tx_executor.block_state.as_mut().expect(BLOCK_STATE_ACCESS_ERR),
            tx_context,
            charge_fee,
            strict_nonce_check,
        )?;

        Ok(())
    }

    fn validate(
        &mut self,
        tx: &AccountTransaction,
        mut remaining_gas: u64,
    ) -> StatefulValidatorResult<(Option<CallInfo>, TransactionReceipt)> {
        let mut execution_resources = ExecutionResources::default();
        let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(tx));

        let limit_steps_by_resources = true;
        let validate_call_info = tx.validate_tx(
            self.tx_executor.block_state.as_mut().expect(BLOCK_STATE_ACCESS_ERR),
            &mut execution_resources,
            tx_context.clone(),
            &mut remaining_gas,
            limit_steps_by_resources,
        )?;

        let tx_receipt = TransactionReceipt::from_account_tx(
            tx,
            &tx_context,
            &self
                .tx_executor
                .block_state
                .as_mut()
                .expect(BLOCK_STATE_ACCESS_ERR)
                .get_actual_state_changes()?,
            &execution_resources,
            validate_call_info.iter(),
            0,
        )?;

        Ok((validate_call_info, tx_receipt))
    }

    pub fn get_nonce(
        &mut self,
        account_address: ContractAddress,
    ) -> StatefulValidatorResult<Nonce> {
        Ok(self
            .tx_executor
            .block_state
            .as_ref()
            .expect(BLOCK_STATE_ACCESS_ERR)
            .get_nonce_at(account_address)?)
    }
}
