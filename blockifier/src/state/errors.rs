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

// TODO(Gilad, 1/12/2022): Derive partialeq/eq in StarknetApiError (or document why that shouldn't
// be done), then derive them here as well.
#[derive(Error, Debug)]
pub enum StateError {
    #[error("Cannot deploy contract at address 0.")]
    OutOfRangeContractAddress,
    #[error("Requested {0:?} is unavailable for deployment.")]
    UnavailableContractAddress(ContractAddress),
    #[error(transparent)]
    StateReaderError(#[from] StateReaderError),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
}
