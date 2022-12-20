use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{CallData, Fee, TransactionVersion};

use super::constants::TRANSFER_ENTRY_POINT_SELECTOR;
use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::state::cached_state::CachedState;
use crate::state::state_reader::StateReader;
use crate::test_utils::{
    TEST_ERC20_CONTRACT_ADDRESS, TEST_ERC20_CONTRACT_CLASS_HASH, TEST_SEQUENCER_ADDRESS,
};
use crate::transaction::errors::{FeeTransferError, TransactionExecutionError};
use crate::transaction::objects::TransactionExecutionResult;

pub fn calculate_tx_fee() -> Fee {
    Fee(1)
}

pub fn execute_fee_transfer<SR: StateReader>(
    state: &mut CachedState<SR>,
    actual_fee: Fee,
    max_fee: Fee,
    caller_address: ContractAddress,
) -> TransactionExecutionResult<CallInfo> {
    if actual_fee > max_fee {
        return Err(FeeTransferError::MaxFeeExceeded { max_fee, actual_fee })?;
    }

    // TODO(Adi, 15/01/2023): Add some function converting `ContractAddress` to felt to SN API.
    let caller_address = *caller_address.0.key();
    let fee_transfer_call = CallEntryPoint {
        // TODO(Adi, 15/01/2023): Replace with a computed ERC20 class hash.
        class_hash: ClassHash(StarkFelt::try_from(TEST_ERC20_CONTRACT_CLASS_HASH)?),
        entry_point_type: EntryPointType::External,
        entry_point_selector: EntryPointSelector(StarkFelt::try_from(
            TRANSFER_ENTRY_POINT_SELECTOR,
        )?),
        calldata: CallData(
            vec![
                // TODO(Adi, 15/01/2023): The sender argument should be removed once
                // `get_caller_address` is implemented.
                StarkFelt::try_from(TEST_SEQUENCER_ADDRESS)?, // Recipient.
                caller_address,                               // Sender.
                StarkFelt::from(actual_fee.0 as u64),         // Amount (lower 128-bit).
                StarkFelt::from(0),                           // Amount (upper 128-bit).
            ]
            .into(),
        ),
        // TODO(Adi, 15/02/2023): Get fee-token address from general config (once).
        storage_address: ContractAddress::try_from(StarkFelt::try_from(
            TEST_ERC20_CONTRACT_ADDRESS,
        )?)?,
    };

    Ok(fee_transfer_call.execute(state)?)
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
