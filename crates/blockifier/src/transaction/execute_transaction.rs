use crate::block_context::BlockContext;
use crate::execution::entry_point::CallInfo;
use crate::state::state_api::State;
use crate::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};

pub trait Transaction {
    fn execute_tx(
        &self,
        state: &mut dyn State,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<Option<CallInfo>>;
}
