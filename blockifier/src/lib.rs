use std::fmt::Debug;

use cached_state::StateReaderError;
use starknet_api::ContractAddress;

pub mod cached_state;
pub mod execution;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum BlockifierError {
    #[error("Cannot deploy contract at address 0.")]
    OutOfRangeAddress,
    #[error("Requested {contract_address:?} is unavailable for deployment.")]
    ContractAddressUnavailable { contract_address: ContractAddress },
    #[error(transparent)]
    StateError(#[from] StateReaderError),
}
