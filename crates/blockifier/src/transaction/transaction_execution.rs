use starknet_api::core::{calculate_contract_address, ContractAddress};
use starknet_api::transaction::{Fee, Transaction as StarknetApiTransaction, TransactionHash};

use crate::abi::constants as abi_constants;
use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{EntryPointExecutionContext, ExecutionResources};
use crate::fee::actual_cost::ActualCost;
use crate::state::cached_state::TransactionalState;
use crate::state::state_api::StateReader;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transactions::{
    DeclareTransaction, DeployAccountTransaction, Executable, ExecutableTransaction,
    InvokeTransaction, L1HandlerTransaction,
};

#[derive(Debug)]
pub enum Transaction {
    AccountTransaction(AccountTransaction),
    L1HandlerTransaction(L1HandlerTransaction),
}

impl Transaction {
    /// Returns the initial gas of the transaction to run with.
    pub fn initial_gas() -> u64 {
        abi_constants::INITIAL_GAS_COST - abi_constants::TRANSACTION_GAS_COST
    }

    pub fn from_api(
        tx: StarknetApiTransaction,
        tx_hash: TransactionHash,
        contract_class: Option<ContractClass>,
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
                let contract_class =
                    contract_class.expect("Declare should be created with a ContractClass");
                let declare_tx = match only_query {
                    true => DeclareTransaction::new_for_query(declare, tx_hash, contract_class),
                    false => DeclareTransaction::new(declare, tx_hash, contract_class),
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

impl<S: StateReader> ExecutableTransaction<S> for L1HandlerTransaction {
    fn execute_raw(
        self,
        state: &mut TransactionalState<'_, S>,
        block_context: &BlockContext,
        _charge_fee: bool,
        _validate: bool,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        let tx_context = self.get_account_tx_context();

        let mut execution_resources = ExecutionResources::default();
        let mut context = EntryPointExecutionContext::new_invoke(block_context, &tx_context);
        let mut remaining_gas = Transaction::initial_gas();
        let execute_call_info =
            self.run_execute(state, &mut execution_resources, &mut context, &mut remaining_gas)?;
        // The calldata includes the "from" field, which is not a part of the payload.
        let l1_handler_payload_size = self.tx.calldata.0.len() - 1;

        let ActualCost { actual_fee, actual_resources } =
            ActualCost::builder_for_l1_handler(block_context, tx_context, l1_handler_payload_size)
                .with_execute_call_info(&execute_call_info)
                .try_add_state_changes(state)?
                .build(&execution_resources)?;

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
            revert_error: None,
        })
    }
}

impl<S: StateReader> ExecutableTransaction<S> for Transaction {
    fn execute_raw(
        self,
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
