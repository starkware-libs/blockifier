use starknet_api::core::{ClassHash, ContractAddress};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateReaderError {
    #[error("Class with hash {0:#?} is not declared.")]
    UndeclaredClassHash(ClassHash),

    /// Represents all unexpected errors that may occur while reading from state.
    #[error("Failed to read from state: {0}.")]
    ReadError(String),
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum CachedStateError {
    #[error("Cannot deploy contract at address 0.")]
    OutOfRangeAddress,
    #[error("Requested {0:?} is unavailable for deployment.")]
    ContractAddressUnavailable(ContractAddress),
    #[error(transparent)]
    StateError(#[from] StateReaderError),
}
