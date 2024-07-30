use cairo_vm::types::errors::program_errors::ProgramError;
use num_bigint::{BigUint, TryFromBigIntError};
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::StarknetApiError;
use thiserror::Error;

use crate::abi::constants;

#[derive(Debug, Error)]
pub enum StateError {
    #[error(transparent)]
    FromBigUint(#[from] TryFromBigIntError<BigUint>),
    #[error(
        "A block hash must be provided for block number > {}.",
        constants::STORED_BLOCK_HASH_BUFFER
    )]
    OldBlockHashNotProvided,
    #[error("Cannot deploy contract at address 0.")]
    OutOfRangeContractAddress,
    #[error(transparent)]
    ProgramError(#[from] ProgramError),
    #[error("Requested {0:?} is unavailable for deployment.")]
    UnavailableContractAddress(ContractAddress),
    #[error("Class with hash {:#064x} is not declared.", **.0)]
    UndeclaredClassHash(ClassHash),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    /// Represents all unexpected errors that may occur while reading from state.
    #[error("Failed to read from state: {0}.")]
    StateReadError(String),
}
