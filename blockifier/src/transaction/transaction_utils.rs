use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::execution::entry_point::CallInfo;
use crate::transaction::errors::{FeeTransferError, TransactionExecutionError};
use crate::transaction::objects::TransactionExecutionResult;

pub fn calculate_tx_fee() -> Fee {
    Fee(1)
}

pub fn execute_fee_transfer(actual_fee: Fee, max_fee: Fee) -> TransactionExecutionResult<CallInfo> {
    if actual_fee > max_fee {
        return Err(FeeTransferError::MaxFeeExceeded { max_fee, actual_fee })?;
    }

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
