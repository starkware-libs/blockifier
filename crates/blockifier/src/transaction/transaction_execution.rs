use starknet_api::transaction::{Fee, L1HandlerTransaction, TransactionSignature};

use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClass;
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
// TODO(Gilad, 15/4/2023): Remove clippy ignore, box large variants.
#[allow(clippy::large_enum_variant)]
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

        let validate_call_info = None;
        // The calldata includes the "from" field, which is not a part of the payload.
        let l1_handler_payload_size = Some(self.calldata.0.len() - 1);
        let actual_resources = calculate_tx_resources(
            execution_resources,
            execute_call_info.as_ref(),
            validate_call_info,
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

impl Transaction {
    pub fn from_api(
        tx: starknet_api::transaction::Transaction,
        contract_class: Option<ContractClass>,
    ) -> Self {
        match tx {
            starknet_api::transaction::Transaction::L1Handler(l1_handler) => {
                Self::L1HandlerTransaction(l1_handler)
            }
            starknet_api::transaction::Transaction::Declare(declare) => Self::AccountTransaction(
                AccountTransaction::Declare(declare, contract_class.unwrap()),
            ),
            starknet_api::transaction::Transaction::Deploy(_) => panic!("No supported!"),
            starknet_api::transaction::Transaction::DeployAccount(deploy_account) => {
                Self::AccountTransaction(AccountTransaction::DeployAccount(deploy_account))
            }
            starknet_api::transaction::Transaction::Invoke(
                starknet_api::transaction::InvokeTransaction::V1(tx),
            ) => Self::AccountTransaction(AccountTransaction::Invoke(tx)),
            _ => panic!("unsupported"),
        }
    }
}
