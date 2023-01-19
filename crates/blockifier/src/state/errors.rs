use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::StarknetApiError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateReaderError {
    #[error("Class with hash {0:#?} is not declared.")]
    UndeclaredClassHash(ClassHash),

    /// Represents all unexpected errors that may occur while reading from state.
    #[error("Failed to read from state: {0}.")]
    ReadError(String),
}

#[derive(Error, Debug)]
pub enum StateError {
    #[error("Cannot deploy contract at address 0.")]
    OutOfRangeContractAddress,
    #[error("Requested {0:?} is unavailable for deployment.")]
    UnavailableContractAddress(ContractAddress),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    StateReaderError(#[from] StateReaderError),
}
