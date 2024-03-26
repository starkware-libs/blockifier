use std::sync::Arc;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use starknet_api::core::{calculate_contract_address, ContractAddress};
use starknet_api::transaction::{Fee, Transaction as StarknetApiTransaction, TransactionHash};

use crate::context::BlockContext;
use crate::execution::contract_class::ClassInfo;
use crate::execution::entry_point::EntryPointExecutionContext;
use crate::fee::actual_cost::TransactionReceipt;
use crate::state::cached_state::TransactionalState;
use crate::state::state_api::StateReader;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::errors::TransactionFeeError;
use crate::transaction::objects::{
    TransactionExecutionInfo, TransactionExecutionResult, TransactionInfo, TransactionInfoCreator,
};
use crate::transaction::transactions::{
    DeclareTransaction, DeployAccountTransaction, Executable, ExecutableTransaction,
    InvokeTransaction, L1HandlerTransaction,
};

// TODO: Move into transaction.rs, makes more sense to be defined there.
#[derive(Debug, derive_more::From)]
pub enum Transaction {
    AccountTransaction(AccountTransaction),
    L1HandlerTransaction(L1HandlerTransaction),
}

impl Transaction {
    pub fn from_api(
        tx: StarknetApiTransaction,
        tx_hash: TransactionHash,
        class_info: Option<ClassInfo>,
        paid_fee_on_l1: Option<Fee>,
        deployed_contract_address: Option<ContractAddress>,
        only_query: bool,
    ) -> TransactionExecutionResult<Self> {
        match tx {
            StarknetApiTransaction::L1Handler(l1_handler) => {
                Ok(Self::L1HandlerTransaction(L1HandlerTransaction {
                    tx: l1_handler,
                    tx_hash,
                    paid_fee_on_l1: paid_fee_on_l1
                        .expect("L1Handler should be created with the fee paid on L1"),
                }))
            }
            StarknetApiTransaction::Declare(declare) => {
                let non_optional_class_info =
                    class_info.expect("Declare should be created with a ClassInfo.");
                let declare_tx = match only_query {
                    true => {
                        DeclareTransaction::new_for_query(declare, tx_hash, non_optional_class_info)
                    }
                    false => DeclareTransaction::new(declare, tx_hash, non_optional_class_info),
                };
                Ok(Self::AccountTransaction(AccountTransaction::Declare(declare_tx?)))
            }
            StarknetApiTransaction::DeployAccount(deploy_account) => {
                let contract_address = match deployed_contract_address {
                    Some(address) => address,
                    None => calculate_contract_address(
                        deploy_account.contract_address_salt(),
                        deploy_account.class_hash(),
                        &deploy_account.constructor_calldata(),
                        ContractAddress::default(),
                    )?,
                };
                let deploy_account_tx = match only_query {
                    true => DeployAccountTransaction::new_for_query(
                        deploy_account,
                        tx_hash,
                        contract_address,
                    ),
                    false => {
                        DeployAccountTransaction::new(deploy_account, tx_hash, contract_address)
                    }
                };
                Ok(Self::AccountTransaction(AccountTransaction::DeployAccount(deploy_account_tx)))
            }
            StarknetApiTransaction::Invoke(invoke) => {
                let invoke_tx = match only_query {
                    true => InvokeTransaction::new_for_query(invoke, tx_hash),
                    false => InvokeTransaction::new(invoke, tx_hash),
                };
                Ok(Self::AccountTransaction(AccountTransaction::Invoke(invoke_tx)))
            }
            _ => unimplemented!(),
        }
    }
}

impl TransactionInfoCreator for Transaction {
    fn create_tx_info(&self) -> TransactionInfo {
        match self {
            Self::AccountTransaction(account_tx) => account_tx.create_tx_info(),
            Self::L1HandlerTransaction(l1_handler_tx) => l1_handler_tx.create_tx_info(),
        }
    }
}

impl<S: StateReader> ExecutableTransaction<S> for L1HandlerTransaction {
    fn execute_raw(
        &self,
        state: &mut TransactionalState<'_, S>,
        block_context: &BlockContext,
        _charge_fee: bool,
        _validate: bool,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        let tx_context = Arc::new(block_context.to_tx_context(self));

        let mut execution_resources = ExecutionResources::default();
        let mut context = EntryPointExecutionContext::new_invoke(tx_context.clone(), true)?;
        let mut remaining_gas = block_context.versioned_constants.tx_initial_gas();
        let execute_call_info =
            self.run_execute(state, &mut execution_resources, &mut context, &mut remaining_gas)?;
        let l1_handler_payload_size = self.payload_size();

        let TransactionReceipt { fee: actual_fee, da_gas, resources: actual_resources, .. } =
            TransactionReceipt::from_l1_handler(
                &tx_context,
                l1_handler_payload_size,
                execute_call_info.iter(),
                &state.get_actual_state_changes()?,
                &execution_resources,
            )?;

        let paid_fee = self.paid_fee_on_l1;
        // For now, assert only that any amount of fee was paid.
        // The error message still indicates the required fee.
        if paid_fee == Fee(0) {
            return Err(TransactionFeeError::InsufficientL1Fee { paid_fee, actual_fee })?;
        }

        Ok(TransactionExecutionInfo {
            validate_call_info: None,
            execute_call_info,
            fee_transfer_call_info: None,
            actual_fee: Fee::default(),
            da_gas,
            revert_error: None,
            actual_resources,
        })
    }
}

impl<S: StateReader> ExecutableTransaction<S> for Transaction {
    fn execute_raw(
        &self,
        state: &mut TransactionalState<'_, S>,
        block_context: &BlockContext,
        charge_fee: bool,
        validate: bool,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        match self {
            Self::AccountTransaction(account_tx) => {
                account_tx.execute_raw(state, block_context, charge_fee, validate)
            }
            Self::L1HandlerTransaction(tx) => {
                tx.execute_raw(state, block_context, charge_fee, validate)
            }
        }
    }
}
