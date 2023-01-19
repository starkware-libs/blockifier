use starknet_api::core::EntryPointSelector;
use starknet_api::transaction::Calldata;

use crate::block_context::BlockContext;
use crate::execution::entry_point::CallInfo;
use crate::state::state_api::State;
use crate::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};

pub trait ExecuteTransaction {
    fn execute_tx(
        &self,
        state: &mut dyn State,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<Option<CallInfo>>;

    fn validate_entrypoint_calldata(&self) -> Calldata;

    fn validate_entry_point_selector() -> EntryPointSelector;
}
