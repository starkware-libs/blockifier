use starknet_api::core::{ClassHash, Nonce};
use starknet_api::transaction::{Fee, TransactionVersion};
use starknet_api::StarknetApiError;
use thiserror::Error;

use crate::execution::errors::EntryPointExecutionError;
use crate::state::errors::StateError;

#[derive(Debug, Error)]
pub enum FeeTransferError {
    #[error("Actual fee ({actual_fee:?}) exceeded max fee ({max_fee:?}).")]
    MaxFeeExceeded { max_fee: Fee, actual_fee: Fee },
}

#[derive(Debug, Error)]
pub enum InvokeTransactionError {
    #[error("Entry point selector must not be specified for an invoke transaction.")]
    SpecifiedEntryPoint,
}

#[derive(Debug, Error)]
pub enum DeclareTransactionError {
    #[error("Class with hash {class_hash:?} is already declared.")]
    ClassAlreadyDeclared { class_hash: ClassHash },
}

#[derive(Debug, Error)]
pub enum TransactionExecutionError {
    #[error(transparent)]
    DeclareTransactionError(#[from] DeclareTransactionError),
    #[error(transparent)]
    EntryPointExecutionError(#[from] EntryPointExecutionError),
    #[error(transparent)]
    FeeTransferError(#[from] FeeTransferError),
    #[error("Invalid transaction nonce. Expected: {expected_nonce:?}; got: {actual_nonce:?}.")]
    InvalidNonce { expected_nonce: Nonce, actual_nonce: Nonce },
    #[error(
        "Transaction version {version:?} is not supported. Supported versions: \
         {allowed_versions:?}."
    )]
    InvalidVersion { version: TransactionVersion, allowed_versions: Vec<TransactionVersion> },
    #[error(transparent)]
    InvokeTransactionError(#[from] InvokeTransactionError),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error("Calling other contracts during '{entry_point_kind}' execution is forbidden.")]
    UnauthorizedInnerCall { entry_point_kind: String },
    #[error("Unexpected holes in the {object} order. Two objects with the same order: {order}.")]
    UnexpectedHoles { object: String, order: usize },
    #[error("Unknown chain ID '{chain_id:?}'.")]
    UnknownChainId { chain_id: String },
}
