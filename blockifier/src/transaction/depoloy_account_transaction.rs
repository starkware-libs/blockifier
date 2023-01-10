use starknet_api::core::ContractAddress;
use starknet_api::transaction::DeployAccountTransaction;

use crate::block_context::BlockContext;
use crate::execution::entry_point::CallInfo;
use crate::execution::execution_utils::execute_deploy;
use crate::state::state_api::State;
use crate::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};

#[cfg(test)]
#[path = "deploy_account_transaction_test.rs"]
mod test;

pub fn execute_tx(
    tx: DeployAccountTransaction,
    state: &mut dyn State,
    block_context: &BlockContext,
    account_tx_context: &AccountTransactionContext,
) -> TransactionExecutionResult<CallInfo> {
    let execute_call = execute_deploy(
        state,
        block_context,
        account_tx_context,
        tx.class_hash,
        tx.contract_address,
        ContractAddress::default(),
        tx.constructor_calldata,
    )?;
    Ok(execute_call)
}
