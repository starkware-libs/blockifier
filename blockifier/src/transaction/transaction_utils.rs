use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{CallData, Fee, TransactionVersion};

use super::constants::TRANSFER_ENTRY_POINT_SELECTOR;
use crate::cached_state::{CachedState, DictStateReader};
use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::test_utils::{TEST_ERC20_CONTRACT_ADDRESS, TEST_ERC20_CONTRACT_CLASS_HASH};
use crate::transaction::errors::{FeeTransferError, TransactionExecutionError};
use crate::transaction::objects::TransactionExecutionResult;

pub fn calculate_tx_fee() -> Fee {
    Fee(1)
}

pub fn execute_fee_transfer(
    actual_fee: Fee,
    max_fee: Fee,
    caller_address: ContractAddress,
    state: CachedState<DictStateReader>,
) -> TransactionExecutionResult<CallInfo> {
    if actual_fee > max_fee {
        return Err(FeeTransferError::MaxFeeExceeded { max_fee, actual_fee })?;
    }

    // TODO(Adi, 15/01/2023): Add some function converting `ContractAddress` to felt to SN API.
    let caller_address_felt = *caller_address.0.key();
    let fee_transfer_call = CallEntryPoint {
        // TODO(Adi, 15/01/2023): Replace with a computed ERC20 class hash.
        class_hash: ClassHash(StarkFelt::try_from(TEST_ERC20_CONTRACT_CLASS_HASH)?),
        entry_point_type: EntryPointType::External,
        entry_point_selector: EntryPointSelector(StarkFelt::try_from(
            TRANSFER_ENTRY_POINT_SELECTOR,
        )?),
        calldata: CallData(vec![
            // TODO(Adi, 15/02/2023): Replace with sequencer_address.
            StarkFelt::try_from(TEST_ERC20_CONTRACT_ADDRESS)?, // Recipient.
            // TODO(Adi, 15/01/2023): Remove once we use the real ERC20 contract, as it is deduced
            // there.
            caller_address_felt, // Sender.
            // TODO(Adi, 15/01/2023): Add some function converting `Fee` to felt to SN API.
            StarkFelt::from(actual_fee.0 as u64), // Amount (lower 128-bit).
            StarkFelt::from(0),                   // Amount (upper 128-bit).
        ]),
        storage_address: caller_address,
    };
    fee_transfer_call.execute(state)?;
    Ok(CallInfo::default())
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
