use cairo_vm::types::errors::program_errors::ProgramError;
use num_bigint::{BigUint, TryFromBigIntError};
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::hash::StarkHash;
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
    #[error("Requested {:#064x} is unavailable for deployment.",***.0)]
    UnavailableContractAddress(ContractAddress),
    // TODO(Aviv, 8/7/2024): use directly in class hash in the next starknet-api
    // version.
    #[error("Class with hash {:#064x} is not declared.", get_nested_class_hash_field(.0))]
    UndeclaredClassHash(ClassHash),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    /// Represents all unexpected errors that may occur while reading from state.
    #[error("Failed to read from state: {0}.")]
    StateReadError(String),
}

fn get_nested_class_hash_field(class_hash: &ClassHash) -> StarkHash {
    class_hash.0
}
