use starknet_api::transaction::{Fee, L1HandlerTransaction, TransactionSignature};

use super::errors::TransactionExecutionError;
use crate::block_context::BlockContext;
use crate::state::cached_state::{CachedState, StateWrapper};
use crate::state::state_api::{State, TransactionalState};
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
    pub fn execute<S: State>(
        self,
        state: &mut CachedState<S>,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        let mut cached_state = CachedState::new(StateWrapper::new(state));

        let tx_execution_result = match self {
            Self::AccountTransaction(account_tx) => {
                account_tx.execute(&mut cached_state, block_context)
            }
            Self::L1HandlerTransaction(tx) => {
                let tx_context = AccountTransactionContext {
                    transaction_hash: tx.transaction_hash,
                    max_fee: Fee::default(),
                    version: tx.version,
                    signature: TransactionSignature::default(),
                    nonce: tx.nonce,
                    sender_address: tx.contract_address,
                };

                let tx_execution_info = TransactionExecutionInfo {
                    validate_call_info: None,
                    execute_call_info: tx.execute(
                        &mut cached_state,
                        block_context,
                        &tx_context,
                        None,
                    )?,
                    fee_transfer_call_info: None,
                    actual_fee: Fee::default(),
                    actual_resources: ResourcesMapping::default(),
                };
                Ok(tx_execution_info)
            }
        };

        match tx_execution_result {
            Ok(tx_execution_info) => {
                // Apply changes.
                state.merge(cached_state);
                Ok(tx_execution_info)
            }
            Err(error) => {
                // Abort, return error.
                cached_state.abort();
                Err(error)
            }
        }
    }
}
