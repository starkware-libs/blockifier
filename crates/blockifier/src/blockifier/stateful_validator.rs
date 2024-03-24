use starknet_api::core::Nonce;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::TransactionHash;
use thiserror::Error;

use crate::blockifier::block::BlockInfo;
use crate::blockifier::bouncer::BouncerInfo;
use crate::blockifier::transaction_executor::{TransactionExecutor, TransactionExecutorError};
use crate::context::{BlockContext, ChainInfo, TransactionContext};
use crate::execution::call_info::CallInfo;
use crate::fee::actual_cost::TransactionReceipt;
use crate::fee::fee_checks::PostValidationReport;
use crate::state::cached_state::{CachedState, GlobalContractCache};
use crate::state::errors::StateError;
use crate::state::state_api::StateReader;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::errors::{TransactionExecutionError, TransactionPreValidationError};
use crate::transaction::objects::{TransactionExecutionInfo, TransactionInfo};
use crate::transaction::transaction_execution::Transaction;
use crate::versioned_constants::VersionedConstants;

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

/// Manages transaction validation for pre-execution flows.
pub struct StatefulValidator<S: StateReader> {
    max_nonce_for_validation_skip: Nonce,
    tx_executor: TransactionExecutor<S>,
}

impl<S: StateReader> StatefulValidator<S> {
    pub fn create(
        state_reader: S,
        max_nonce_for_validation_skip: Nonce,
        // TODO(Arni, 30/04/2024): Get block_info and chain_info from the most logical place.
        block_info: BlockInfo,
        chain_info: ChainInfo,
        // TODO(Arni, 30/04/2024): Consider bundling these variables into a struct.
        validate_max_n_steps: u32,
        max_recursion_depth: usize,
        global_contract_cache_size: usize,
    ) -> StatefulValidatorResult<Self> {
        let versioned_constants = VersionedConstants::latest_constants_with_overrides(
            validate_max_n_steps,
            max_recursion_depth,
        );
        let global_contract_cache = GlobalContractCache::new(global_contract_cache_size);
        let state = CachedState::new(state_reader, global_contract_cache);

        let block_context =
            BlockContext::new_unchecked(&block_info, &chain_info, &versioned_constants);
        let tx_executor = TransactionExecutor::new(state, block_context);

        Ok(Self { max_nonce_for_validation_skip, tx_executor })
    }

    pub fn perform_validations(
        &mut self,
        tx: AccountTransaction,
        deploy_account_tx_hash: Option<TransactionHash>,
    ) -> StatefulValidatorResult<()> {
        let tx_context = self.tx_executor.block_context.to_tx_context(&tx);
        // Deploy account transactions should be fully executed, since the constructor must run
        // before `__validate_deploy__`. The execution already includes all necessary validations,
        // so they are skipped here.
        if let AccountTransaction::DeployAccount(_) = tx {
            let (_tx_execution_info, _bouncer_info) = self.execute(tx)?;

            return Ok(());
        }

        // First, we check if the transaction should be skipped due to the deploy account not being
        // processed. It is done before the pre-validations checks because, in these checks, we
        // change the state (more precisely, we increment the nonce).
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

    // TODO(Arni, 30/04/2024): Use the create method to implement create_for_testing.
    #[cfg(any(feature = "testing", test))]
    pub fn create_for_testing(
        state_reader: S,
        block_info: BlockInfo,
        chain_info: ChainInfo,
    ) -> StatefulValidatorResult<Self> {
        use crate::state::cached_state::GLOBAL_CONTRACT_CACHE_SIZE_FOR_TEST;

        let global_contract_cache = GlobalContractCache::new(GLOBAL_CONTRACT_CACHE_SIZE_FOR_TEST);
        let state = CachedState::new(state_reader, global_contract_cache);

        let block_context = BlockContext::new_unchecked(
            &block_info,
            &chain_info,
            VersionedConstants::latest_constants(),
        );
        let tx_executor = TransactionExecutor::new(state, block_context);

        Ok(Self { max_nonce_for_validation_skip: Nonce(StarkFelt::ONE), tx_executor })
    }

    fn execute(
        &mut self,
        tx: AccountTransaction,
    ) -> StatefulValidatorResult<(TransactionExecutionInfo, BouncerInfo)> {
        Ok(self.tx_executor.execute(Transaction::AccountTransaction(tx), true)?)
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
