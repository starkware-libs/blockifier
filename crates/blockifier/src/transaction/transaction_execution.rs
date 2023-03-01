use starknet_api::transaction::{Fee, L1HandlerTransaction, TransactionSignature};

use super::transaction_utils::execute_transactionally;
use crate::block_context::BlockContext;
use crate::state::cached_state::CachedState;
use crate::state::state_api::StateReader;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::objects::{
    AccountTransactionContext, ResourcesMapping, TransactionExecutionInfo,
    TransactionExecutionResult,
};
use crate::transaction::transactions::Executable;

#[derive(Debug)]
pub enum Transaction {
    AccountTransaction(AccountTransaction),
    L1HandlerTransaction(L1HandlerTransaction),
}

impl Transaction {
    /// Executes the transaction in a transactional manner
    /// (if it fails, given state does not modify).
    pub fn execute<S: StateReader>(
        self,
        state: &mut CachedState<S>,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        execute_transactionally(self, state, block_context, Transaction::execute_raw)
    }

    /// Executes the transaction in a non-transactional manner.
    fn execute_raw<S: StateReader>(
        self,
        state: &mut CachedState<S>,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        let tx_execution_info = match self {
            Self::AccountTransaction(account_tx) => account_tx.execute(state, block_context)?,
            Self::L1HandlerTransaction(tx) => {
                let tx_context = AccountTransactionContext {
                    transaction_hash: tx.transaction_hash,
                    max_fee: Fee::default(),
                    version: tx.version,
                    signature: TransactionSignature::default(),
                    nonce: tx.nonce,
                    sender_address: tx.contract_address,
                };

                TransactionExecutionInfo {
                    validate_call_info: None,
                    execute_call_info: tx.execute(state, block_context, &tx_context, None)?,
                    fee_transfer_call_info: None,
                    actual_fee: Fee::default(),
                    actual_resources: ResourcesMapping::default(),
                }
            }
        };

        Ok(tx_execution_info)
    }
}
