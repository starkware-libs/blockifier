use std::sync::Arc;

use once_cell::sync::Lazy;
use starknet_api::calldata;
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{
    Calldata, DeclareTransaction, DeployAccountTransaction, Fee, InvokeTransaction,
    TransactionVersion,
};

use crate::abi::abi_utils::get_selector;
use crate::block_context::BlockContext;
use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::state::state_api::State;
use crate::transaction::constants::{
    TRANSFER_ENTRY_POINT_NAME, VALIDATE_DECLARE_ENTRY_POINT_NAME, VALIDATE_DEPLOY_ENTRY_POINT_NAME,
    VALIDATE_ENTRY_POINT_NAME,
};
use crate::transaction::errors::{FeeTransferError, TransactionExecutionError};
use crate::transaction::execute_transaction::ExecuteTransaction;
use crate::transaction::objects::{
    AccountTransactionContext, ResourcesMapping, TransactionExecutionInfo,
    TransactionExecutionResult,
};
use crate::transaction::transaction_utils::calculate_tx_fee;

/// Represents a paid StarkNet transaction.
pub enum AccountTransaction {
    Declare(DeclareTransaction),
    DeployAccount(DeployAccountTransaction),
    Invoke(InvokeTransaction),
}

impl AccountTransaction {
    fn get_account_transaction_context(&self) -> AccountTransactionContext {
        match self {
            Self::Declare(tx) => AccountTransactionContext {
                transaction_hash: tx.transaction_hash,
                max_fee: tx.max_fee,
                version: tx.version,
                signature: tx.signature.clone(),
                nonce: tx.nonce,
                sender_address: tx.sender_address,
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
        static ALLOWED_VERSIONS: Lazy<Vec<TransactionVersion>> =
            Lazy::new(|| vec![TransactionVersion(StarkFelt::from(1))]);
        if ALLOWED_VERSIONS.contains(&version) {
            Ok(())
        } else {
            Err(TransactionExecutionError::InvalidVersion {
                version,
                allowed_versions: &ALLOWED_VERSIONS,
            })
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
            entry_point_selector: get_selector(TRANSFER_ENTRY_POINT_NAME),
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
            Self::execute_fee_transfer(state, block_context, account_tx_context, actual_fee)?;

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
            Self::Declare(tx) => {
                // Validate declare transaction.
                validate_call_info = Self::validate_tx(
                    state,
                    block_context,
                    &account_tx_context,
                    get_selector(VALIDATE_DECLARE_ENTRY_POINT_NAME),
                    // `__validate_declare__` is expected to get one parameter: 'class_hash'.
                    calldata![tx.class_hash.0],
                )?;

                // Execute declare transaction.
                tx.execute_tx(state, block_context, &account_tx_context)?;
                execute_call_info = None;
            }
            Self::DeployAccount(tx) => {
                // Execute deploy account transaction.
                execute_call_info =
                    Some(tx.execute_tx(state, block_context, &account_tx_context)?);

                // Validate deploy account transaction.
                // `__validate_deploy__` is expected to get the arguments: class_hash, salt,
                // constructor_calldata.
                let mut validate_calldata_vec = vec![tx.class_hash.0, tx.contract_address_salt.0];
                validate_calldata_vec.extend(&(*tx.constructor_calldata.0));
                validate_call_info = Self::validate_tx(
                    state,
                    block_context,
                    &account_tx_context,
                    get_selector(VALIDATE_DEPLOY_ENTRY_POINT_NAME),
                    Calldata(Arc::new(validate_calldata_vec)),
                )?;
            }
            Self::Invoke(tx) => {
                // Validate invoke transaction.
                validate_call_info = Self::validate_tx(
                    state,
                    block_context,
                    &account_tx_context,
                    get_selector(VALIDATE_ENTRY_POINT_NAME),
                    // The validation calldata for invoke transaction is the same calldata as for
                    // the execution itself.
                    tx.calldata.clone(),
                )?;

                // Execute invoke transaction.
                execute_call_info =
                    Some(tx.execute_tx(state, block_context, &account_tx_context)?);
            }
        };

        // Charge fee.
        let actual_resources = ResourcesMapping::default();
        let (actual_fee, fee_transfer_call_info) =
            Self::charge_fee(state, block_context, &account_tx_context)?;

        Ok(TransactionExecutionInfo {
            validate_call_info,
            execute_call_info,
            fee_transfer_call_info,
            actual_fee,
            actual_resources,
        })
    }
}
