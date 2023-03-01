use starknet_api::transaction::Fee;

use super::objects::TransactionExecutionInfo;
use crate::block_context::BlockContext;
use crate::execution::entry_point::CallInfo;
use crate::state::cached_state::{CachedState, MutRefState, TransactionalState};
use crate::state::state_api::StateReader;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::TransactionExecutionResult;

pub fn calculate_tx_fee(_block_context: &BlockContext) -> Fee {
    Fee(2)
}

pub fn verify_no_calls_to_other_contracts(
    call_info: &CallInfo,
    entry_point_kind: String,
) -> TransactionExecutionResult<()> {
    let invoked_contract_address = call_info.call.storage_address;
    if call_info
        .into_iter()
        .any(|inner_call| inner_call.call.storage_address != invoked_contract_address)
    {
        return Err(TransactionExecutionError::UnauthorizedInnerCall { entry_point_kind });
    }

    Ok(())
}

pub fn execute_transactionally<'a, S, T, ExecuteCallback>(
    tx: T,
    state: &'a mut CachedState<S>,
    block_context: &BlockContext,
    execute_callback: ExecuteCallback,
) -> TransactionExecutionResult<TransactionExecutionInfo>
where
    S: StateReader,
    ExecuteCallback: FnOnce(
        T,
        &mut TransactionalState<'a, S>,
        &BlockContext,
    ) -> TransactionExecutionResult<TransactionExecutionInfo>,
{
    let mut transactional_state = CachedState::new(MutRefState::new(state));
    let execution_result = execute_callback(tx, &mut transactional_state, block_context);

    match execution_result {
        Ok(value) => {
            transactional_state.commit();
            Ok(value)
        }
        Err(error) => {
            transactional_state.abort();
            Err(error)
        }
    }
}
