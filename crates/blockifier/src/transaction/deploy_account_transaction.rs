use starknet_api::core::ContractAddress;
use starknet_api::transaction::DeployAccountTransaction;

use crate::block_context::BlockContext;
use crate::execution::entry_point::CallInfo;
use crate::execution::execution_utils::execute_deployment;
use crate::state::state_api::State;
use crate::transaction::execute_transaction::ExecuteTransaction;
use crate::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};

#[cfg(test)]
#[path = "deploy_account_transaction_test.rs"]
mod test;

impl ExecuteTransaction for DeployAccountTransaction {
    fn execute_tx(
        self,
        state: &mut dyn State,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<CallInfo> {
        Ok(execute_deployment(
            state,
            block_context,
            account_tx_context,
            self.class_hash,
            self.contract_address,
            ContractAddress::default(),
            self.constructor_calldata,
        )?)
    }
}
