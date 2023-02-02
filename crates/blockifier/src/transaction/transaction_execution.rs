use starknet_api::state::StateDiff;
use starknet_api::transaction::{Fee, L1HandlerTransaction, TransactionSignature};

use crate::block_context::BlockContext;
use crate::state::state_api::State;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::objects::{
    AccountTransactionContext, ResourcesMapping, TransactionExecutionInfo,
    TransactionExecutionResult,
};
use crate::transaction::transactions::Executable;

pub enum Transaction {
    AccountTransaction(AccountTransaction),
    L1HandlerTransaction(L1HandlerTransaction),
}

impl Transaction {
    pub fn execute(
        self,
        state: &mut dyn State,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<(StateDiff, TransactionExecutionInfo)> {
        match self {
            Self::AccountTransaction(account_tx) => account_tx.execute(state, block_context),
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
                    execute_call_info: tx.execute(state, block_context, &tx_context)?,
                    fee_transfer_call_info: None,
                    actual_fee: Fee::default(),
                    actual_resources: ResourcesMapping::default(),
                };
                Ok((state.to_state_diff(), tx_execution_info))
            }
        }
    }
}
