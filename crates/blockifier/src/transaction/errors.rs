use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Fee, TransactionVersion};
use starknet_api::StarknetApiError;
use thiserror::Error;

use crate::execution::errors::EntryPointExecutionError;
use crate::state::errors::StateError;

#[derive(Debug, Error)]
pub enum TransactionExecutionError {
    #[error("Cairo resource names must be contained in fee cost dict.")]
    CairoResourcesNotContainedInFeeCosts,
    #[error(
        "Declare transaction version {declare_version:?} must have a contract class of Cairo \
         version {cairo_version:?}."
    )]
    ContractClassVersionMismatch { declare_version: TransactionVersion, cairo_version: u64 },
    #[error("Contract constructor execution has failed.")]
    ContractConstructorExecutionFailed(#[source] EntryPointExecutionError),
    #[error("Class with hash {class_hash:?} is already declared.")]
    DeclareTransactionError { class_hash: ClassHash },
    #[error(transparent)]
    EntryPointExecutionError(#[from] EntryPointExecutionError),
    #[error("Transaction execution has failed.")]
    ExecutionError(#[source] EntryPointExecutionError),
    #[error("Actual fee ({actual_fee:?}) exceeded max fee ({max_fee:?}).")]
    FeeTransferError { max_fee: Fee, actual_fee: Fee },
    #[error("Actual fee ({actual_fee:?}) exceeded paid fee on L1 ({paid_fee:?}).")]
    InsufficientL1Fee { paid_fee: Fee, actual_fee: Fee },
    #[error(
        "Invalid transaction nonce of contract at address {address:?}. Expected: \
         {expected_nonce:?}; got: {actual_nonce:?}."
    )]
    InvalidNonce { address: ContractAddress, expected_nonce: Nonce, actual_nonce: Nonce },
    #[error(
        "Transaction version {version:?} is not supported. Supported versions: \
         {allowed_versions:?}."
    )]
    InvalidVersion { version: TransactionVersion, allowed_versions: Vec<TransactionVersion> },
    #[error("Max fee ({max_fee:?}) exceeds balance (Uint256({balance_low:?}, {balance_high:?})).")]
    MaxFeeExceedsBalance { max_fee: Fee, balance_low: StarkFelt, balance_high: StarkFelt },
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
    #[error("Transaction validation has failed.")]
    ValidateTransactionError(#[source] EntryPointExecutionError),
}
