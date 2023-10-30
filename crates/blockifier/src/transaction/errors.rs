use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Fee, Resource, TransactionVersion};
use starknet_api::StarknetApiError;
use thiserror::Error;

use crate::execution::call_info::Retdata;
use crate::execution::errors::EntryPointExecutionError;
use crate::state::errors::StateError;

#[derive(Debug, Error)]
pub enum TransactionFeeError {
    #[error("Cairo resource names must be contained in fee cost dict.")]
    CairoResourcesNotContainedInFeeCosts,
    #[error("Actual fee ({actual_fee:?}) exceeded max fee ({max_fee:?}).")]
    FeeTransferError { max_fee: Fee, actual_fee: Fee },
    #[error("Actual fee ({actual_fee:?}) exceeded paid fee on L1 ({paid_fee:?}).")]
    InsufficientL1Fee { paid_fee: Fee, actual_fee: Fee },
    #[error("Max fee ({max_fee:?}) exceeds balance (Uint256({balance_low:?}, {balance_high:?})).")]
    MaxFeeExceedsBalance { max_fee: Fee, balance_low: StarkFelt, balance_high: StarkFelt },
    #[error("Max fee ({max_fee:?}) is too low. Minimum fee: {min_fee:?}.")]
    MaxFeeTooLow { min_fee: Fee, max_fee: Fee },
    #[error(
        "Max L1 gas price ({max_l1_gas_price:?}) is lower than the actual gas price: \
         {actual_l1_gas_price:?}."
    )]
    MaxL1GasPriceTooLow { max_l1_gas_price: Fee, actual_l1_gas_price: Fee },
    #[error(
        "Max L1 gas amount ({max_l1_gas_amount:?}) is lower than the minimal gas amount: \
         {minimal_l1_gas_amount:?}."
    )]
    MaxL1GasAmountTooLow { max_l1_gas_amount: u64, minimal_l1_gas_amount: u64 },
    #[error("Missing bounds for resource: {:?}.", resource)]
    MissingResourceBounds { resource: Resource },
    #[error(transparent)]
    StateError(#[from] StateError),
}

#[derive(Debug, Error)]
pub enum TransactionExecutionError {
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
    #[error(
        "Invalid order number for {object}. Order: {order} exceeds the maximum order limit: \
         {max_order}."
    )]
    InvalidOrder { object: String, order: usize, max_order: usize },
    #[error("The `validate` entry point should return `VALID`. Got {actual:?}.")]
    InvalidValidateReturnData { actual: Retdata },
    #[error(
        "Transaction version {version:?} is not supported. Supported versions: \
         {allowed_versions:?}."
    )]
    InvalidVersion { version: TransactionVersion, allowed_versions: Vec<TransactionVersion> },
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error(transparent)]
    TransactionFeeError(#[from] TransactionFeeError),
    #[error(transparent)]
    TransactionPreValidationError(#[from] TransactionPreValidationError),
    #[error("Unexpected holes in the {object} order. No object with the order: {order}.")]
    UnexpectedHoles { object: String, order: usize },
    #[error("Transaction validation has failed.")]
    ValidateTransactionError(#[source] EntryPointExecutionError),
}

#[derive(Debug, Error)]
pub enum TransactionPreValidationError {
    #[error(
        "Invalid transaction nonce of contract at address {address:?}. Account nonce: \
         {account_nonce:?}; got: {incoming_tx_nonce:?}."
    )]
    InvalidNonce { address: ContractAddress, account_nonce: Nonce, incoming_tx_nonce: Nonce },
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error(transparent)]
    TransactionFeeError(#[from] TransactionFeeError),
}
