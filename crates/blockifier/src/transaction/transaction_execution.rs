use starknet_api::transaction::{Fee, L1HandlerTransaction, TransactionSignature};

use crate::block_context::BlockContext;
use crate::execution::entry_point::{ExecutionResourcesManager, StateContext};
use crate::state::cached_state::TransactionalState;
use crate::state::state_api::StateReader;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::objects::{
    AccountTransactionContext, ResourcesMapping, TransactionExecutionInfo,
    TransactionExecutionResult,
};
use crate::transaction::transactions::{Executable, ExecutableTransaction};

#[derive(Debug)]
pub enum Transaction {
    AccountTransaction(AccountTransaction),
    L1HandlerTransaction(L1HandlerTransaction),
}

impl<S: StateReader> ExecutableTransaction<S> for L1HandlerTransaction {
    fn execute_raw(
        self,
        state: &mut TransactionalState<'_, S>,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        let tx_context = AccountTransactionContext {
            transaction_hash: self.transaction_hash,
            max_fee: Fee::default(),
            version: self.version,
            signature: TransactionSignature::default(),
            nonce: self.nonce,
            sender_address: self.contract_address,
        };
        let resources_manager = &mut ExecutionResourcesManager::default();
        let mut ctx = StateContext {
            state,
            resources_manager,
            block_context,
            account_tx_context: &tx_context,
        };
        Ok(TransactionExecutionInfo {
            validate_call_info: None,
            execute_call_info: self.run_execute(&mut ctx, None)?,
            fee_transfer_call_info: None,
            actual_fee: Fee::default(),
            actual_resources: ResourcesMapping::default(),
        })
    }
}

impl<S: StateReader> ExecutableTransaction<S> for Transaction {
    fn execute_raw(
        self,
        state: &mut TransactionalState<'_, S>,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        match self {
            Self::AccountTransaction(account_tx) => account_tx.execute_raw(state, block_context),
            Self::L1HandlerTransaction(tx) => tx.execute_raw(state, block_context),
        }
    }
}
