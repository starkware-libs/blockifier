use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{Calldata, Fee, TransactionVersion};

use super::constants::TRANSFER_ENTRY_POINT_SELECTOR;
use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::state::state_api::State;
use crate::test_utils::{TEST_ERC20_CONTRACT_ADDRESS, TEST_SEQUENCER_ADDRESS};
use crate::transaction::errors::{FeeTransferError, TransactionExecutionError};
use crate::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};

pub fn calculate_tx_fee() -> Fee {
    Fee(1)
}

pub fn execute_fee_transfer(
    state: &mut dyn State,
    actual_fee: Fee,
    max_fee: Fee,
    account_tx_context: &AccountTransactionContext,
) -> TransactionExecutionResult<CallInfo> {
    if actual_fee > max_fee {
        return Err(FeeTransferError::MaxFeeExceeded { max_fee, actual_fee })?;
    }

    // TODO(Adi, 15/01/2023): Add some function converting `ContractAddress` to felt to SN API.
    let fee_transfer_call = CallEntryPoint {
        // TODO(Adi, 15/01/2023): Replace with a computed ERC20 class hash.
        class_hash: None,
        entry_point_type: EntryPointType::External,
        entry_point_selector: EntryPointSelector(StarkFelt::try_from(
            TRANSFER_ENTRY_POINT_SELECTOR,
        )?),
        calldata: Calldata(
            vec![
                // TODO(Adi, 15/01/2023): The sender argument should be removed once
                // `get_caller_address` is implemented.
                StarkFelt::try_from(TEST_SEQUENCER_ADDRESS)?, // Recipient.
                *account_tx_context.sender_address.0.key(),   // Sender.
                StarkFelt::from(actual_fee.0 as u64),         // Amount (lower 128-bit).
                StarkFelt::from(0),                           // Amount (upper 128-bit).
            ]
            .into(),
        ),
        // TODO(Adi, 15/02/2023): Get fee-token address from general config (once).
        storage_address: ContractAddress::try_from(StarkFelt::try_from(
            TEST_ERC20_CONTRACT_ADDRESS,
        )?)?,
        caller_address: account_tx_context.sender_address,
    };

    Ok(fee_transfer_call.execute(state, account_tx_context)?)
}

pub fn verify_tx_version(tx_version: TransactionVersion) -> TransactionExecutionResult<()> {
    // TODO(Adi, 10/12/2022): Consider using the lazy_static crate or some other solution, so the
    // allowed_versions variable will only be constructed once.
    let allowed_versions = vec![TransactionVersion(StarkFelt::from(1))];
    if allowed_versions.contains(&tx_version) {
        Ok(())
    } else {
        Err(TransactionExecutionError::InvalidTransactionVersion { tx_version, allowed_versions })
    }
}
