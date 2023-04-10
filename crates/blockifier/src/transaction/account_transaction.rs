use std::mem;

use itertools::concat;
use starknet_api::calldata;
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, DeclareTransaction, DeployAccountTransaction, Fee, InvokeTransactionV1,
    TransactionVersion,
};

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants as abi_constants;
use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{
    CallEntryPoint, CallInfo, CallType, ExecutionContext, ExecutionResources,
};
use crate::state::cached_state::TransactionalState;
use crate::state::state_api::{State, StateReader};
use crate::transaction::constants;
use crate::transaction::errors::{
    FeeTransferError, TransactionExecutionError, ValidateTransactionError,
};
use crate::transaction::objects::{
    AccountTransactionContext, TransactionExecutionInfo, TransactionExecutionResult,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transaction_utils::{
    calculate_tx_fee, calculate_tx_resources, verify_no_calls_to_other_contracts,
};
use crate::transaction::transactions::{Executable, ExecutableTransaction};

#[cfg(test)]
#[path = "account_transactions_test.rs"]
mod test;

/// Represents a paid StarkNet transaction.
#[derive(Debug)]
// TODO(Gilad, 15/4/2023): Remove clippy ignore, box large variants.
#[allow(clippy::large_enum_variant)]
pub enum AccountTransaction {
    Declare(DeclareTransaction, ContractClass),
    DeployAccount(DeployAccountTransaction),
    Invoke(InvokeTransactionV1),
}

impl AccountTransaction {
    fn tx_type(&self) -> TransactionType {
        match self {
            AccountTransaction::Declare(_, _) => TransactionType::Declare,
            AccountTransaction::DeployAccount(_) => TransactionType::DeployAccount,
            AccountTransaction::Invoke(_) => TransactionType::InvokeFunction,
        }
    }

    fn validate_entry_point_selector(&self) -> EntryPointSelector {
        let validate_entry_point_name = match self {
            Self::Declare(_, _) => constants::VALIDATE_DECLARE_ENTRY_POINT_NAME,
            Self::DeployAccount(_) => constants::VALIDATE_DEPLOY_ENTRY_POINT_NAME,
            Self::Invoke(_) => constants::VALIDATE_ENTRY_POINT_NAME,
        };
        selector_from_name(validate_entry_point_name)
    }

    // Calldata for validation contains transaction fields that cannot be obtained by calling
    // `get_tx_info()`.
    fn validate_entrypoint_calldata(&self) -> Calldata {
        match self {
            Self::Declare(tx, _contract_class) => calldata![tx.class_hash().0],
            Self::DeployAccount(tx) => {
                let validate_calldata = concat(vec![
                    vec![tx.class_hash.0, tx.contract_address_salt.0],
                    (*tx.constructor_calldata.0).clone(),
                ]);
                Calldata(validate_calldata.into())
            }
            // Calldata for validation is the same calldata as for the execution itself.
            Self::Invoke(tx) => Calldata(tx.calldata.0.clone()),
        }
    }

    fn get_account_transaction_context(&self) -> AccountTransactionContext {
        match self {
            Self::Declare(tx, _contract_class) => AccountTransactionContext {
                transaction_hash: tx.transaction_hash(),
                max_fee: tx.max_fee(),
                version: match tx {
                    DeclareTransaction::V0(_) => TransactionVersion(StarkFelt::from(0)),
                    DeclareTransaction::V1(_) => TransactionVersion(StarkFelt::from(1)),
                    DeclareTransaction::V2(_) => TransactionVersion(StarkFelt::from(2)),
                },
                signature: tx.signature(),
                nonce: tx.nonce(),
                sender_address: tx.sender_address(),
            },
            Self::DeployAccount(tx) => AccountTransactionContext {
                transaction_hash: tx.transaction_hash,
                max_fee: tx.max_fee,
                version: tx.version,
                signature: tx.signature.clone(),
                nonce: tx.nonce,
                sender_address: tx.contract_address,
            },
            Self::Invoke(tx) => AccountTransactionContext {
                transaction_hash: tx.transaction_hash,
                max_fee: tx.max_fee,
                version: TransactionVersion(StarkFelt::from(1)),
                signature: tx.signature.clone(),
                nonce: tx.nonce,
                sender_address: tx.sender_address,
            },
        }
    }

    fn verify_tx_version(&self, version: TransactionVersion) -> TransactionExecutionResult<()> {
        let allowed_versions: Vec<TransactionVersion> = match self {
            Self::Declare(_, _) => {
                // Support old versions in order to allow bootstrapping of a new system.
                vec![TransactionVersion(StarkFelt::from(0)), TransactionVersion(StarkFelt::from(1))]
            }
            _ => vec![TransactionVersion(StarkFelt::from(1))],
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
        if account_tx_context.version == TransactionVersion(StarkFelt::from(0)) {
            return Ok(());
        }

        let current_nonce = state.get_nonce_at(account_tx_context.sender_address)?;
        if current_nonce != account_tx_context.nonce {
            return Err(TransactionExecutionError::InvalidNonce {
                expected_nonce: current_nonce,
                actual_nonce: account_tx_context.nonce,
            });
        }

        // Increment nonce.
        Ok(state.increment_nonce(account_tx_context.sender_address)?)
    }

    fn validate_tx(
        &self,
        state: &mut dyn State,
        execution_resources: &mut ExecutionResources,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        if account_tx_context.version == TransactionVersion(StarkFelt::from(0)) {
            return Ok(None);
        }

        let validate_call = CallEntryPoint {
            entry_point_type: EntryPointType::External,
            entry_point_selector: self.validate_entry_point_selector(),
            calldata: self.validate_entrypoint_calldata(),
            class_hash: None,
            storage_address: account_tx_context.sender_address,
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
        };
        let mut execution_context = ExecutionContext::default();

        let validate_call_info = validate_call
            .execute(
                state,
                execution_resources,
                &mut execution_context,
                block_context,
                account_tx_context,
            )
            .map_err(ValidateTransactionError::ValidateExecutionFailed)?;
        verify_no_calls_to_other_contracts(
            &validate_call_info,
            String::from(constants::VALIDATE_ENTRY_POINT_NAME),
        )?;

        Ok(Some(validate_call_info))
    }

    fn charge_fee(
        state: &mut dyn State,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<(Fee, Option<CallInfo>)> {
        let no_fee = Fee::default();
        if account_tx_context.max_fee == no_fee {
            // Fee charging is not enforced in some tests.
            return Ok((no_fee, None));
        }

        let actual_fee = calculate_tx_fee(block_context);
        let fee_transfer_call_info = Self::execute_fee_transfer(
            state,
            &mut ExecutionResources::default(),
            block_context,
            account_tx_context,
            actual_fee,
        )?;

        Ok((actual_fee, Some(fee_transfer_call_info)))
    }

    fn execute_fee_transfer(
        state: &mut dyn State,
        execution_resources: &mut ExecutionResources,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        actual_fee: Fee,
    ) -> TransactionExecutionResult<CallInfo> {
        let max_fee = account_tx_context.max_fee;
        if actual_fee > max_fee {
            return Err(FeeTransferError::MaxFeeExceeded { max_fee, actual_fee })?;
        }

        // The least significant 128 bits of the amount transferred.
        let lsb_amount = StarkFelt::from(actual_fee.0 as u64);
        // The most significant 128 bits of the amount transferred.
        let msb_amount = StarkFelt::from(0);

        let fee_transfer_call = CallEntryPoint {
            class_hash: None,
            entry_point_type: EntryPointType::External,
            entry_point_selector: selector_from_name(constants::TRANSFER_ENTRY_POINT_NAME),
            calldata: calldata![
                *block_context.sequencer_address.0.key(), // Recipient.
                lsb_amount,
                msb_amount
            ],
            storage_address: block_context.fee_token_address,
            caller_address: account_tx_context.sender_address,
            call_type: CallType::Call,
        };
        let mut execution_context = ExecutionContext::default();

        Ok(fee_transfer_call.execute(
            state,
            execution_resources,
            &mut execution_context,
            block_context,
            account_tx_context,
        )?)
    }
}

impl<S: StateReader> ExecutableTransaction<S> for AccountTransaction {
    fn execute_raw(
        mut self,
        state: &mut TransactionalState<'_, S>,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        let account_tx_context = self.get_account_transaction_context();
        self.verify_tx_version(account_tx_context.version)?;
        Self::handle_nonce(&account_tx_context, state)?;

        // Handle transaction-type specific execution.
        let validate_call_info: Option<CallInfo>;
        let execute_call_info: Option<CallInfo>;
        let tx_type = self.tx_type();
        let mut execution_resources = ExecutionResources::default();
        match self {
            Self::Declare(ref tx, ref mut contract_class) => {
                let contract_class = Some(mem::take(contract_class));

                // Validate.
                validate_call_info = self.validate_tx(
                    state,
                    &mut execution_resources,
                    block_context,
                    &account_tx_context,
                )?;

                // Execute.
                execute_call_info = tx.run_execute(
                    state,
                    &mut execution_resources,
                    block_context,
                    &account_tx_context,
                    contract_class,
                )?;
            }
            Self::DeployAccount(ref tx) => {
                // Execute the constructor of the deployed class.
                execute_call_info = tx.run_execute(
                    state,
                    &mut execution_resources,
                    block_context,
                    &account_tx_context,
                    None,
                )?;

                // Validate.
                validate_call_info = self.validate_tx(
                    state,
                    &mut execution_resources,
                    block_context,
                    &account_tx_context,
                )?;
            }
            Self::Invoke(ref tx) => {
                // Validate.
                validate_call_info = self.validate_tx(
                    state,
                    &mut execution_resources,
                    block_context,
                    &account_tx_context,
                )?;

                // Execute.
                execute_call_info = tx.run_execute(
                    state,
                    &mut execution_resources,
                    block_context,
                    &account_tx_context,
                    None,
                )?;
            }
        };

        //  Handle fee.
        let (mut actual_resources, l1_gas_usage) = calculate_tx_resources(
            execution_resources,
            execute_call_info.as_ref(),
            validate_call_info.as_ref(),
            tx_type,
            state,
            None,
        )?;

        let (n_storage_updates, n_modified_contracts, n_class_updates) =
            state.count_actual_state_changes();

        // Charge fee.
        let (actual_fee, fee_transfer_call_info) =
            Self::charge_fee(state, block_context, &account_tx_context)?;

        // Adds the l1 gas usage to the actual resources for the bouncer.
        actual_resources.0.insert(abi_constants::GAS_USAGE.to_string(), l1_gas_usage);

        let tx_execution_info = TransactionExecutionInfo {
            validate_call_info,
            execute_call_info,
            fee_transfer_call_info,
            actual_fee,
            actual_resources,
            n_storage_updates,
            n_modified_contracts,
            n_class_updates,
        };
        Ok(tx_execution_info)
    }
}
