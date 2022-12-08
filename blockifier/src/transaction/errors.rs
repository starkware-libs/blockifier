use starknet_api::transaction::{Fee, TransactionVersion};
use starknet_api::StarknetApiError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransactionExecutionError {
    #[error(transparent)]
    FeeTransferError(#[from] FeeTransferError),
    #[error(
        "Transaction version {transaction_version:?} is not supported. Supported versions: \
         {supported_versions:?}."
    )]
    InvalidTransactionVersion {
        transaction_version: TransactionVersion,
        supported_versions: Vec<TransactionVersion>,
    },
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
}

#[derive(Error, Eq, PartialEq, Debug)]
pub enum FeeTransferError {
    #[error("Actual fee ({actual_fee:?}) exceeded max fee ({max_fee:?}).")]
    MaxFeeExceeded { max_fee: Fee, actual_fee: Fee },
}
