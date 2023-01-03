use starknet_api::calldata;
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{Calldata, Fee, InvokeTransaction, TransactionVersion};

use crate::abi::abi_utils::get_selector_from_name;
use crate::block_context::BlockContext;
use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::state::state_api::State;
use crate::transaction::constants::{TRANSFER_ENTRY_POINT_NAME, VALIDATE_ENTRY_POINT_NAME};
use crate::transaction::errors::{FeeTransferError, TransactionExecutionError};
use crate::transaction::execute_transaction::ExecuteTransaction;
use crate::transaction::objects::{
    AccountTransactionContext, ResourcesMapping, TransactionExecutionInfo,
    TransactionExecutionResult,
};
use crate::transaction::transaction_utils::calculate_tx_fee;

pub enum AccountTransaction {
    Invoke(InvokeTransaction),
}

impl AccountTransaction {
    fn get_account_transaction_context(&self) -> AccountTransactionContext {
        match self {
            Self::Invoke(tx) => AccountTransactionContext {
                transaction_hash: tx.transaction_hash,
                max_fee: tx.max_fee,
                version: tx.version,
                signature: tx.signature.clone(),
                nonce: tx.nonce,
                sender_address: tx.sender_address,
            },
        }
    }

    fn handle_nonce(
        account_tx_context: &AccountTransactionContext,
        state: &mut dyn State,
    ) -> TransactionExecutionResult<()> {
        let current_nonce = *state.get_nonce_at(account_tx_context.sender_address)?;
        if current_nonce != account_tx_context.nonce {
            return Err(TransactionExecutionError::InvalidNonce {
                expected_nonce: current_nonce,
                actual_nonce: account_tx_context.nonce,
            });
        }

        // Increment nonce.
        Ok(state.increment_nonce(account_tx_context.sender_address)?)
    }

    fn verify_tx_version(version: TransactionVersion) -> TransactionExecutionResult<()> {
        // TODO(Adi, 10/12/2022): Consider using the lazy_static crate or some other solution, so
        // the allowed_versions variable will only be constructed once.
        let allowed_versions = vec![TransactionVersion(StarkFelt::from(1))];
        if allowed_versions.contains(&version) {
            Ok(())
        } else {
            Err(TransactionExecutionError::InvalidVersion { version, allowed_versions })
        }
    }

    fn validate_tx(
        state: &mut dyn State,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        validate_entry_point_selector: EntryPointSelector,
        validate_entry_point_calldata: Calldata,
    ) -> TransactionExecutionResult<CallInfo> {
        let validate_call = CallEntryPoint {
            entry_point_type: EntryPointType::External,
            entry_point_selector: validate_entry_point_selector,
            calldata: validate_entry_point_calldata,
            class_hash: None,
            storage_address: account_tx_context.sender_address,
            caller_address: ContractAddress::default(),
        };

        Ok(validate_call.execute(state, block_context, account_tx_context)?)
    }

    fn execute_fee_transfer(
        state: &mut dyn State,
        actual_fee: Fee,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
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
            entry_point_selector: get_selector_from_name(TRANSFER_ENTRY_POINT_NAME),
            calldata: calldata![
                *block_context.sequencer_address.0.key(), // Recipient.
                lsb_amount,
                msb_amount
            ],
            storage_address: block_context.fee_token_address,
            caller_address: account_tx_context.sender_address,
        };

        Ok(fee_transfer_call.execute(state, block_context, account_tx_context)?)
    }

    fn charge_fee(
        state: &mut dyn State,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<(Fee, CallInfo)> {
        let actual_fee = calculate_tx_fee(block_context);
        let fee_transfer_call_info =
            Self::execute_fee_transfer(state, actual_fee, block_context, account_tx_context)?;

        Ok((actual_fee, fee_transfer_call_info))
    }

    pub fn execute(
        self,
        state: &mut dyn State,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        let account_tx_context = self.get_account_transaction_context();
        Self::verify_tx_version(account_tx_context.version)?;
        Self::handle_nonce(&account_tx_context, state)?;

        // Handle transaction-type specific execution.
        let validate_call_info;
        let execute_call_info;
        match self {
            Self::Invoke(tx) => {
                // Validate invoke transaction.
                validate_call_info = Self::validate_tx(
                    state,
                    block_context,
                    &account_tx_context,
                    get_selector_from_name(VALIDATE_ENTRY_POINT_NAME),
                    // The validation calldata for invoke transaction is the same calldata as for
                    // the execution itself.
                    tx.calldata.clone(),
                )?;

                // Execute invoke transaction.
                execute_call_info = tx.execute_tx(state, block_context, &account_tx_context)?;
            }
        };

        // Charge fee.
        // TODO(Adi, 25/12/2022): Get actual resources.
        let actual_resources = ResourcesMapping::default();
        let (actual_fee, fee_transfer_call_info) =
            Self::charge_fee(state, block_context, &account_tx_context)?;

        Ok(TransactionExecutionInfo {
            validate_call_info,
            execute_call_info: Some(execute_call_info),
            fee_transfer_call_info,
            actual_fee,
            actual_resources,
        })
    }
}
