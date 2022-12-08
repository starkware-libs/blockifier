use starknet_api::transaction::{Fee, TransactionVersion};
use starknet_api::StarknetApiError;
use thiserror::Error;

use crate::execution::errors::EntryPointExecutionError;

#[derive(Error, Debug)]
pub enum FeeTransferError {
    #[error("Actual fee ({actual_fee:?}) exceeded max fee ({max_fee:?}).")]
    MaxFeeExceeded { max_fee: Fee, actual_fee: Fee },
}

#[derive(Error, Debug)]
pub enum TransactionExecutionError {
    #[error(transparent)]
    EntryPointExecutionError(#[from] EntryPointExecutionError),
    #[error(transparent)]
    FeeTransferError(#[from] FeeTransferError),
    #[error(
        "Transaction version {tx_version:?} is not supported. Supported versions: \
         {allowed_versions:?}."
    )]
    InvalidTransactionVersion {
        tx_version: TransactionVersion,
        allowed_versions: Vec<TransactionVersion>,
    },
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
}
