use starknet_api::core::{calculate_contract_address, ContractAddress};
use starknet_api::transaction::{
    Fee, Transaction as StarknetApiTransaction, TransactionHash, TransactionSignature,
};

use crate::abi::constants as abi_constants;
use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{EntryPointExecutionContext, ExecutionResources};
use crate::fee::fee_utils::calculate_tx_fee;
use crate::state::cached_state::{StateChangesCount, TransactionalState};
use crate::state::state_api::StateReader;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{
    AccountTransactionContext, TransactionExecutionInfo, TransactionExecutionResult,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transaction_utils::{calculate_l1_gas_usage, calculate_tx_resources};
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
}

impl Transaction {
    pub fn from_api(
        tx: StarknetApiTransaction,
        tx_hash: TransactionHash,
        contract_class: Option<ContractClass>,
        paid_fee_on_l1: Option<Fee>,
        deployed_contract_address: Option<ContractAddress>,
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
                Ok(Self::AccountTransaction(AccountTransaction::Declare(DeclareTransaction::new(
                    declare,
                    tx_hash,
                    contract_class.expect("Declare should be created with a ContractClass"),
                )?)))
            }
            StarknetApiTransaction::DeployAccount(deploy_account) => {
                let contract_address = match deployed_contract_address {
                    Some(address) => address,
                    None => calculate_contract_address(
                        deploy_account.contract_address_salt,
                        deploy_account.class_hash,
                        &deploy_account.constructor_calldata,
                        ContractAddress::default(),
                    )?,
                };

                Ok(Self::AccountTransaction(AccountTransaction::DeployAccount(
                    DeployAccountTransaction { tx: deploy_account, tx_hash, contract_address },
                )))
            }
            StarknetApiTransaction::Invoke(invoke) => {
                Ok(Self::AccountTransaction(AccountTransaction::Invoke(InvokeTransaction {
                    tx: invoke,
                    tx_hash,
                })))
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
        // TODO(Dori, 1/9/2023): NEW_TOKEN_SUPPORT token address should depend on tx version.
        let fee_token_address = block_context.deprecated_fee_token_address;
        let tx = &self.tx;
        let tx_context = AccountTransactionContext {
            transaction_hash: self.tx_hash,
            max_fee: Fee::default(),
            version: tx.version,
            signature: TransactionSignature::default(),
            nonce: tx.nonce,
            sender_address: tx.contract_address,
        };
        let mut resources = ExecutionResources::default();
        let mut context = EntryPointExecutionContext::new_invoke(block_context, &tx_context);
        let mut remaining_gas = Transaction::initial_gas();
        let execute_call_info =
            self.run_execute(state, &mut resources, &mut context, &mut remaining_gas)?;

        let call_infos =
            if let Some(call_info) = execute_call_info.as_ref() { vec![call_info] } else { vec![] };
        // The calldata includes the "from" field, which is not a part of the payload.
        let l1_handler_payload_size = Some(tx.calldata.0.len() - 1);
        let state_changes =
            state.get_actual_state_changes_for_fee_charge(fee_token_address, None)?;
        let l1_gas_usage = calculate_l1_gas_usage(
            &call_infos,
            StateChangesCount::from(&state_changes),
            l1_handler_payload_size,
        )?;
        let actual_resources =
            calculate_tx_resources(&resources, l1_gas_usage, TransactionType::L1Handler)?;
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
