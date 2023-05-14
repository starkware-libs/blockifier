use starknet_api::transaction::{
    Fee, L1HandlerTransaction, Transaction as StarknetApiTransaction, TransactionSignature,
};

use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::ExecutionContext;
use crate::state::cached_state::TransactionalState;
use crate::state::state_api::StateReader;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::objects::{
    AccountTransactionContext, TransactionExecutionInfo, TransactionExecutionResult,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transaction_utils::calculate_tx_resources;
use crate::transaction::transactions::{DeclareTransaction, Executable, ExecutableTransaction};

#[derive(Debug)]
pub enum Transaction {
    AccountTransaction(AccountTransaction),
    L1HandlerTransaction(L1HandlerTransaction),
}

impl Transaction {
    pub fn from_api(tx: StarknetApiTransaction, contract_class: Option<ContractClass>) -> Self {
        match tx {
            StarknetApiTransaction::L1Handler(l1_handler) => Self::L1HandlerTransaction(l1_handler),
            StarknetApiTransaction::Declare(declare) => {
                Self::AccountTransaction(AccountTransaction::Declare(DeclareTransaction {
                    tx: declare,
                    contract_class: contract_class
                        .expect("Declare should be created with a ContractClass"),
                }))
            }
            StarknetApiTransaction::DeployAccount(deploy_account) => {
                Self::AccountTransaction(AccountTransaction::DeployAccount(deploy_account))
            }
            StarknetApiTransaction::Invoke(invoke) => {
                Self::AccountTransaction(AccountTransaction::Invoke(invoke))
            }
            _ => unimplemented!(),
        }
    }
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
        let mut context = ExecutionContext::new(block_context.clone(), tx_context);
        let execute_call_info = self.run_execute(state, &mut context)?;

        let call_infos =
            if let Some(call_info) = execute_call_info.as_ref() { vec![call_info] } else { vec![] };
        // The calldata includes the "from" field, which is not a part of the payload.
        let l1_handler_payload_size = Some(self.calldata.0.len() - 1);
        let actual_resources = calculate_tx_resources(
            context.resources,
            &call_infos,
            TransactionType::L1Handler,
            state,
            l1_handler_payload_size,
        )?;

        Ok(TransactionExecutionInfo {
            validate_call_info: None,
            execute_call_info,
            fee_transfer_call_info: None,
            actual_fee: Fee::default(),
            actual_resources,
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
