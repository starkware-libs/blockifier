use starknet_api::transaction::{Fee, Transaction as StarknetApiTransaction, TransactionSignature};

use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::ExecutionContext;
use crate::fee::fee_utils::calculate_tx_fee;
use crate::state::cached_state::TransactionalState;
use crate::state::state_api::StateReader;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{
    AccountTransactionContext, TransactionExecutionInfo, TransactionExecutionResult,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transaction_utils::calculate_tx_resources;
use crate::transaction::transactions::{
    DeclareTransaction, Executable, ExecutableTransaction, L1HandlerTransaction,
};

#[derive(Debug)]
pub enum Transaction {
    AccountTransaction(AccountTransaction),
    L1HandlerTransaction(L1HandlerTransaction),
}

impl Transaction {
    pub fn from_api(
        tx: StarknetApiTransaction,
        contract_class: Option<ContractClass>,
        paid_fee_on_l1: Option<Fee>,
    ) -> TransactionExecutionResult<Self> {
        match tx {
            StarknetApiTransaction::L1Handler(l1_handler) => {
                Ok(Self::L1HandlerTransaction(L1HandlerTransaction {
                    tx: l1_handler,
                    paid_fee_on_l1: paid_fee_on_l1
                        .expect("L1Handler should be created with the fee paid on L1"),
                }))
            }
            StarknetApiTransaction::Declare(declare) => {
                Ok(Self::AccountTransaction(AccountTransaction::Declare(DeclareTransaction::new(
                    declare,
                    contract_class.expect("Declare should be created with a ContractClass"),
                )?)))
            }
            StarknetApiTransaction::DeployAccount(deploy_account) => {
                Ok(Self::AccountTransaction(AccountTransaction::DeployAccount(deploy_account)))
            }
            StarknetApiTransaction::Invoke(invoke) => {
                Ok(Self::AccountTransaction(AccountTransaction::Invoke(invoke)))
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
        let tx = &self.tx;
        let tx_context = AccountTransactionContext {
            transaction_hash: tx.transaction_hash,
            max_fee: Fee::default(),
            version: tx.version,
            signature: TransactionSignature::default(),
            nonce: tx.nonce,
            sender_address: tx.contract_address,
        };
        let mut context = ExecutionContext::new(block_context.clone(), tx_context);
        let execute_call_info = self.run_execute(state, &mut context)?;

        let call_infos =
            if let Some(call_info) = execute_call_info.as_ref() { vec![call_info] } else { vec![] };
        // The calldata includes the "from" field, which is not a part of the payload.
        let l1_handler_payload_size = Some(tx.calldata.0.len() - 1);
        let actual_resources = calculate_tx_resources(
            context.resources,
            &call_infos,
            TransactionType::L1Handler,
            state,
            l1_handler_payload_size,
        )?;
        let actual_fee = calculate_tx_fee(&actual_resources, &context.block_context)?;
        let paid_fee = self.paid_fee_on_l1;
        // For now, assert only that any amount of fee was paid.
        // The error message still indicates the required fee.
        if paid_fee == Fee(0) {
            return Err(TransactionExecutionError::InsufficientL1Fee { paid_fee, actual_fee });
        }

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
