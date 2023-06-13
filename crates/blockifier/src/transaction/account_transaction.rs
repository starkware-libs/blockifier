use cairo_felt::Felt252;
use itertools::concat;
use starknet_api::calldata;
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, DeployAccountTransaction, Fee, InvokeTransaction, TransactionVersion,
};

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants as abi_constants;
use crate::block_context::BlockContext;
use crate::execution::entry_point::{
    CallEntryPoint, CallInfo, CallType, EntryPointExecutionContext,
};
use crate::fee::fee_utils::calculate_tx_fee;
use crate::state::cached_state::TransactionalState;
use crate::state::state_api::{State, StateReader};
use crate::transaction::constants;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{
    AccountTransactionContext, ResourcesMapping, TransactionExecutionInfo,
    TransactionExecutionResult,
};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transaction_utils::{
    calculate_tx_resources, update_remaining_gas, verify_no_calls_to_other_contracts,
};
use crate::transaction::transactions::{DeclareTransaction, Executable, ExecutableTransaction};

#[cfg(test)]
#[path = "account_transactions_test.rs"]
mod test;

/// Represents a paid StarkNet transaction.
#[derive(Debug)]
pub enum AccountTransaction {
    Declare(DeclareTransaction),
    DeployAccount(DeployAccountTransaction),
    Invoke(InvokeTransaction),
}

impl AccountTransaction {
    fn tx_type(&self) -> TransactionType {
        match self {
            AccountTransaction::Declare(_) => TransactionType::Declare,
            AccountTransaction::DeployAccount(_) => TransactionType::DeployAccount,
            AccountTransaction::Invoke(_) => TransactionType::InvokeFunction,
        }
    }

    pub fn max_fee(&self) -> Fee {
        match self {
            AccountTransaction::Declare(declare) => declare.tx().max_fee(),
            AccountTransaction::DeployAccount(deploy_account) => deploy_account.max_fee,
            AccountTransaction::Invoke(invoke) => invoke.max_fee(),
        }
    }

    fn validate_entry_point_selector(&self) -> EntryPointSelector {
        let validate_entry_point_name = match self {
            Self::Declare(_) => constants::VALIDATE_DECLARE_ENTRY_POINT_NAME,
            Self::DeployAccount(_) => constants::VALIDATE_DEPLOY_ENTRY_POINT_NAME,
            Self::Invoke(_) => constants::VALIDATE_ENTRY_POINT_NAME,
        };
        selector_from_name(validate_entry_point_name)
    }

    // Calldata for validation contains transaction fields that cannot be obtained by calling
    // `get_tx_info()`.
    fn validate_entrypoint_calldata(&self) -> Calldata {
        match self {
            Self::Declare(tx) => calldata![tx.tx().class_hash().0],
            Self::DeployAccount(tx) => {
                let validate_calldata = concat(vec![
                    vec![tx.class_hash.0, tx.contract_address_salt.0],
                    (*tx.constructor_calldata.0).clone(),
                ]);
                Calldata(validate_calldata.into())
            }
            // Calldata for validation is the same calldata as for the execution itself.
            Self::Invoke(tx) => tx.calldata(),
        }
    }

    fn get_account_transaction_context(&self) -> AccountTransactionContext {
        match self {
            Self::Declare(tx) => {
                let tx = &tx.tx();
                AccountTransactionContext {
                    transaction_hash: tx.transaction_hash(),
                    max_fee: tx.max_fee(),
                    version: tx.version(),
                    signature: tx.signature(),
                    nonce: tx.nonce(),
                    sender_address: tx.sender_address(),
                }
            }
            Self::DeployAccount(tx) => AccountTransactionContext {
                transaction_hash: tx.transaction_hash,
                max_fee: tx.max_fee,
                version: tx.version,
                signature: tx.signature.clone(),
                nonce: tx.nonce,
                sender_address: tx.contract_address,
            },
            Self::Invoke(tx) => AccountTransactionContext {
                transaction_hash: tx.transaction_hash(),
                max_fee: tx.max_fee(),
                version: match tx {
                    InvokeTransaction::V0(_) => TransactionVersion(StarkFelt::from(0_u8)),
                    InvokeTransaction::V1(_) => TransactionVersion(StarkFelt::from(1_u8)),
                },
                signature: tx.signature(),
                nonce: tx.nonce(),
                sender_address: tx.sender_address(),
            },
        }
    }

    fn verify_tx_version(&self, version: TransactionVersion) -> TransactionExecutionResult<()> {
        let allowed_versions: Vec<TransactionVersion> = match self {
            // Support `Declare` of version 0 in order to allow bootstrapping of a new system.
            Self::Declare(_) => {
                vec![
                    TransactionVersion(StarkFelt::from(0_u8)),
                    TransactionVersion(StarkFelt::from(1_u8)),
                    TransactionVersion(StarkFelt::from(2_u8)),
                ]
            }
            Self::Invoke(_) => {
                vec![
                    TransactionVersion(StarkFelt::from(0_u8)),
                    TransactionVersion(StarkFelt::from(1_u8)),
                ]
            }
            _ => vec![TransactionVersion(StarkFelt::from(1_u8))],
        };
        if allowed_versions.contains(&version) {
            Ok(())
        } else {
            Err(TransactionExecutionError::InvalidVersion { version, allowed_versions })
        }
    }

    fn handle_nonce(
        account_tx_context: &AccountTransactionContext,
        state: &mut dyn State,
    ) -> TransactionExecutionResult<()> {
        if account_tx_context.version == TransactionVersion(StarkFelt::from(0_u8)) {
            return Ok(());
        }

        let address = account_tx_context.sender_address;
        let current_nonce = state.get_nonce_at(address)?;
        if current_nonce != account_tx_context.nonce {
            return Err(TransactionExecutionError::InvalidNonce {
                address,
                expected_nonce: current_nonce,
                actual_nonce: account_tx_context.nonce,
            });
        }

        // Increment nonce.
        Ok(state.increment_nonce(address)?)
    }

    fn validate_tx(
        &self,
        state: &mut dyn State,
        context: &mut EntryPointExecutionContext,
        remaining_gas: &mut Felt252,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        if context.account_tx_context.version == TransactionVersion(StarkFelt::from(0_u8)) {
            return Ok(None);
        }

        let storage_address = context.account_tx_context.sender_address;
        let validate_call = CallEntryPoint {
            entry_point_type: EntryPointType::External,
            entry_point_selector: self.validate_entry_point_selector(),
            calldata: self.validate_entrypoint_calldata(),
            class_hash: None,
            code_address: None,
            storage_address,
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
            initial_gas: remaining_gas.clone(),
        };

        let validate_call_info = validate_call
            .execute(state, context)
            .map_err(TransactionExecutionError::ValidateTransactionError)?;
        verify_no_calls_to_other_contracts(
            &validate_call_info,
            String::from(constants::VALIDATE_ENTRY_POINT_NAME),
        )?;
        update_remaining_gas(remaining_gas, &validate_call_info);

        Ok(Some(validate_call_info))
    }

    fn enforce_fee(&self) -> bool {
        self.max_fee() != Fee(0)
    }

    /// Handles nonce, checks balance covers max fee, and (when applicable) runs the validation
    /// phase.
    /// Returns the `CallInfo` of the validation phase, if applicable.
    fn process_validation_state<S: StateReader>(
        &self,
        state: &mut TransactionalState<'_, S>,
        context: &mut ExecutionContext,
        remaining_gas: &mut Felt252,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        // Handle nonce.
        Self::handle_nonce(&context.account_tx_context, state)?;

        // Check fee balance.
        if self.enforce_fee() {
            let (balance_low, balance_high) = state.get_fee_token_balance(
                &context.block_context,
                &context.account_tx_context.sender_address,
            )?;
            // TODO(Dori, 1/7/2023): If and when Fees can be more than 128 bit integers, this check
            //   should be updated.
            if balance_high == StarkFelt::from(0_u8)
                && balance_low < StarkFelt::from(context.account_tx_context.max_fee.0)
            {
                return Err(TransactionExecutionError::MaxFeeExceedsBalance {
                    max_fee: context.account_tx_context.max_fee,
                    balance_low,
                    balance_high,
                });
            }
        }

        // Validate transaction (if applicable).
        match &self {
            Self::Declare(_) | Self::Invoke(_) => self.validate_tx(state, context, remaining_gas),
            Self::DeployAccount(_) => Ok(None),
        }
    }

    fn charge_fee(
        state: &mut dyn State,
        context: &mut EntryPointExecutionContext,
        resources: &ResourcesMapping,
    ) -> TransactionExecutionResult<(Fee, Option<CallInfo>)> {
        let no_fee = Fee::default();
        if context.account_tx_context.max_fee == no_fee {
            // Fee charging is not enforced in some tests.
            return Ok((no_fee, None));
        }

        let actual_fee = calculate_tx_fee(resources, &context.block_context)?;
        let fee_transfer_call_info = Self::execute_fee_transfer(state, context, actual_fee)?;

        Ok((actual_fee, Some(fee_transfer_call_info)))
    }

    fn execute_fee_transfer(
        state: &mut dyn State,
        context: &mut EntryPointExecutionContext,
        actual_fee: Fee,
    ) -> TransactionExecutionResult<CallInfo> {
        let max_fee = context.account_tx_context.max_fee;
        if actual_fee > max_fee {
            return Err(TransactionExecutionError::FeeTransferError { max_fee, actual_fee });
        }

        // The least significant 128 bits of the amount transferred.
        let lsb_amount = StarkFelt::from(actual_fee.0);
        // The most significant 128 bits of the amount transferred.
        let msb_amount = StarkFelt::from(0_u8);

        let storage_address = context.block_context.fee_token_address;
        // The fee-token contract is a Cairo 0 contract, hence the initial gas is irrelevant.
        let initial_gas = abi_constants::INITIAL_GAS_COST.into();
        let fee_transfer_call = CallEntryPoint {
            class_hash: None,
            code_address: None,
            entry_point_type: EntryPointType::External,
            entry_point_selector: selector_from_name(constants::TRANSFER_ENTRY_POINT_NAME),
            calldata: calldata![
                *context.block_context.sequencer_address.0.key(), // Recipient.
                lsb_amount,
                msb_amount
            ],
            storage_address,
            caller_address: context.account_tx_context.sender_address,
            call_type: CallType::Call,
            initial_gas,
        };

        Ok(fee_transfer_call.execute(state, context)?)
    }

    fn run_execute<S: State>(
        &self,
        state: &mut S,
        context: &mut ExecutionContext,
        remaining_gas: &mut Felt252,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        match &self {
            Self::Declare(tx) => tx.run_execute(state, context, remaining_gas),
            Self::DeployAccount(tx) => tx.run_execute(state, context, remaining_gas),
            Self::Invoke(tx) => tx.run_execute(state, context, remaining_gas),
        }
    }
}

impl<S: StateReader> ExecutableTransaction<S> for AccountTransaction {
    fn execute_raw(
        self,
        state: &mut TransactionalState<'_, S>,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        let account_tx_context = self.get_account_transaction_context();
        self.verify_tx_version(account_tx_context.version)?;
<<<<<<< HEAD
        let mut context = ExecutionContext::new(block_context.clone(), account_tx_context);
||||||| 0af6406
        Self::handle_nonce(&account_tx_context, state)?;

        // Handle transaction-type specific execution.
        let validate_call_info: Option<CallInfo>;
        let execute_call_info: Option<CallInfo>;
        let tx_type = self.tx_type();
        let mut context = ExecutionContext::new(block_context.clone(), account_tx_context);
=======
        Self::handle_nonce(&account_tx_context, state)?;

        // Handle transaction-type specific execution.
        let validate_call_info: Option<CallInfo>;
        let execute_call_info: Option<CallInfo>;
        let tx_type = self.tx_type();
        let mut context =
            EntryPointExecutionContext::new(block_context.clone(), account_tx_context);
>>>>>>> origin/main-v0.12.0
        let mut remaining_gas = Transaction::initial_gas();

        // Pre-process the nonce / fee check / validation state changes.
        let early_validate_call_info =
            self.process_validation_state(state, &mut context, &mut remaining_gas)?;

        // Handle transaction-type specific execution.
        // The validation phase in a `DeployAccount` transaction happens after execution.
        let execute_call_info = self.run_execute(state, &mut context, &mut remaining_gas)?;
        let validate_call_info = match &self {
            Self::DeployAccount(_) => self.validate_tx(state, &mut context, &mut remaining_gas)?,
            Self::Declare(_) | Self::Invoke(_) => early_validate_call_info,
        };

        // Handle fee.
        let non_optional_call_infos = vec![validate_call_info.as_ref(), execute_call_info.as_ref()]
            .into_iter()
            .flatten()
            .collect::<Vec<&CallInfo>>();
        let actual_resources = calculate_tx_resources(
            context.resources,
            &non_optional_call_infos,
            self.tx_type(),
            state,
            None,
        )?;

        // Charge fee.
        // Recreate the context to empty the execution resources.
        let mut context =
            EntryPointExecutionContext::new(context.block_context, context.account_tx_context);
        let (actual_fee, fee_transfer_call_info) =
            Self::charge_fee(state, &mut context, &actual_resources)?;

        let tx_execution_info = TransactionExecutionInfo {
            validate_call_info,
            execute_call_info,
            fee_transfer_call_info,
            actual_fee,
            actual_resources,
            revert_error: None,
        };
        Ok(tx_execution_info)
    }
}
