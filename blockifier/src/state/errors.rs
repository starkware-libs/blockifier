use starknet_api::core::{ClassHash, ContractAddress};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateReaderError {
    #[error("Class with hash {0:#?} is not declared.")]
    UndeclaredClassHash(ClassHash),
}

#[derive(thiserror::Error, Debug)]
pub enum CachedStateError {
    #[error("Cannot deploy contract at address 0.")]
    OutOfRangeAddress,
    #[error("Requested {0:?} is unavailable for deployment.")]
    ContractAddressUnavailable(ContractAddress),
    #[error(transparent)]
    StateError(#[from] StateReaderError),
}
