use starknet_api::api_core::{ClassHash, ContractAddress};
use starknet_api::StarknetApiError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("Cannot deploy contract at address 0.")]
    OutOfRangeContractAddress,
    #[error("Requested {0:?} is unavailable for deployment.")]
    UnavailableContractAddress(ContractAddress),
    #[error("Class with hash {0:#?} is not declared.")]
    UndeclaredClassHash(ClassHash),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    /// Represents all unexpected errors that may occur while reading from state.
    #[error("Failed to read from state: {0}.")]
    StateReadError(String),
}
