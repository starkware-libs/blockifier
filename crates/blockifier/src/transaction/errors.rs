use num_bigint::BigUint;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector, Nonce};
use starknet_api::transaction::{Fee, TransactionVersion};
use starknet_api::StarknetApiError;
use starknet_types_core::felt::FromStrError;
use thiserror::Error;

use crate::execution::call_info::Retdata;
use crate::execution::errors::{ConstructorEntryPointExecutionError, EntryPointExecutionError};
use crate::execution::stack_trace::gen_transaction_execution_error_trace;
use crate::fee::fee_checks::FeeCheckError;
use crate::state::errors::StateError;

// TODO(Yoni, 1/9/2024): implement Display for Fee.
#[derive(Debug, Error)]
pub enum TransactionFeeError {
    #[error("Cairo resource names must be contained in fee cost dict.")]
    CairoResourcesNotContainedInFeeCosts,
    #[error(transparent)]
    ExecuteFeeTransferError(#[from] EntryPointExecutionError),
    #[error("Actual fee ({}) exceeded max fee ({}).", actual_fee.0, max_fee.0)]
    FeeTransferError { max_fee: Fee, actual_fee: Fee },
    #[error("Actual fee ({}) exceeded paid fee on L1 ({}).", actual_fee.0, paid_fee.0)]
    InsufficientL1Fee { paid_fee: Fee, actual_fee: Fee },
    #[error(
        "L1 gas bounds (max amount: {max_amount}, max price: {max_price}) exceed balance \
         ({balance})."
    )]
    L1GasBoundsExceedBalance { max_amount: u64, max_price: u128, balance: BigUint },
    #[error("Max fee ({}) exceeds balance ({balance}).", max_fee.0, )]
    MaxFeeExceedsBalance { max_fee: Fee, balance: BigUint },
    #[error("Max fee ({}) is too low. Minimum fee: {}.", max_fee.0, min_fee.0)]
    MaxFeeTooLow { min_fee: Fee, max_fee: Fee },
    #[error(
        "Max L1 gas price ({max_l1_gas_price}) is lower than the actual gas price: \
         {actual_l1_gas_price}."
    )]
    MaxL1GasPriceTooLow { max_l1_gas_price: u128, actual_l1_gas_price: u128 },
    #[error(
        "Max L1 gas amount ({max_l1_gas_amount}) is lower than the minimal gas amount: \
         {minimal_l1_gas_amount}."
    )]
    MaxL1GasAmountTooLow { max_l1_gas_amount: u64, minimal_l1_gas_amount: u64 },
    #[error("Missing L1 gas bounds in resource bounds.")]
    MissingL1GasBounds,
    #[error(transparent)]
    StateError(#[from] StateError),
}

#[derive(Debug, Error)]
pub enum TransactionExecutionError {
    #[error(
        "Declare transaction version {} must have a contract class of Cairo \
         version {cairo_version:?}.", **declare_version
    )]
    ContractClassVersionMismatch { declare_version: TransactionVersion, cairo_version: u64 },
    #[error(
        "Contract constructor execution has failed:\n{}",
        String::from(gen_transaction_execution_error_trace(self))
    )]
    ContractConstructorExecutionFailed(#[from] ConstructorEntryPointExecutionError),
    #[error("Class with hash {:#064x} is already declared.", **class_hash)]
    DeclareTransactionError { class_hash: ClassHash },
    #[error(
        "Transaction execution has failed:\n{}",
        String::from(gen_transaction_execution_error_trace(self))
    )]
    ExecutionError {
        error: EntryPointExecutionError,
        class_hash: ClassHash,
        storage_address: ContractAddress,
        selector: EntryPointSelector,
    },
    #[error(transparent)]
    FeeCheckError(#[from] FeeCheckError),
    #[error(transparent)]
    FromStr(#[from] FromStrError),
    #[error("The `validate` entry point should return `VALID`. Got {actual:?}.")]
    InvalidValidateReturnData { actual: Retdata },
    #[error(
        "Transaction version {:?} is not supported. Supported versions: \
         {:?}.", **version, allowed_versions.iter().map(|v| **v).collect::<Vec<_>>()
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
    #[error(transparent)]
    TryFromIntError(#[from] std::num::TryFromIntError),
    #[error("Transaction size exceeds the maximum block capacity.")]
    TransactionTooLarge,
    #[error(
        "Transaction validation has failed:\n{}",
        String::from(gen_transaction_execution_error_trace(self))
    )]
    ValidateTransactionError {
        error: EntryPointExecutionError,
        class_hash: ClassHash,
        storage_address: ContractAddress,
        selector: EntryPointSelector,
    },
    #[error(
        "Invalid segment structure: PC {0} was visited, but the beginning of the segment {1} was \
         not."
    )]
    InvalidSegmentStructure(usize, usize),
}

#[derive(Debug, Error)]
pub enum TransactionPreValidationError {
    #[error(
        "Invalid transaction nonce of contract at address {:#064x}. Account nonce: \
         {:#064x}; got: {:#064x}.", ***address, **account_nonce, **incoming_tx_nonce
    )]
    InvalidNonce { address: ContractAddress, account_nonce: Nonce, incoming_tx_nonce: Nonce },
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error(transparent)]
    TransactionFeeError(#[from] TransactionFeeError),
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Unsupported transaction type: {0}")]
    UnknownTransactionType(String),
}

#[derive(Debug, Error)]
pub enum NumericConversionError {
    #[error("Conversion of {0} to u128 unsuccessful.")]
    U128ToUsizeError(u128),
}
