use starknet_api::transaction::{Fee, L1HandlerTransaction, TransactionSignature};

use crate::block_context::BlockContext;
use crate::execution::entry_point::ExecutionResources;
use crate::state::cached_state::TransactionalState;
use crate::state::state_api::StateReader;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::objects::{
    AccountTransactionContext, TransactionExecutionInfo, TransactionExecutionResult,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transaction_utils::calculate_tx_resources;
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
        let mut execution_resources = ExecutionResources::default();
        let execute_call_info =
            self.run_execute(state, &mut execution_resources, block_context, &tx_context, None)?;

        let actual_resources = calculate_tx_resources(
            execution_resources,
            &[execute_call_info.as_ref()],
            TransactionType::L1Handler,
            state,
            // The calldata includes the "from" field, which is not a part of the payload. We thus
            // subtract 1.
            Some(self.calldata.0.len() - 1),
        )?;

        let (n_storage_updates, n_modified_contracts, n_class_updates) =
            state.count_actual_state_changes();

        Ok(TransactionExecutionInfo {
            validate_call_info: None,
            execute_call_info,
            fee_transfer_call_info: None,
            actual_fee: Fee::default(),
            actual_resources,
            n_storage_updates,
            n_modified_contracts,
            n_class_updates,
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
