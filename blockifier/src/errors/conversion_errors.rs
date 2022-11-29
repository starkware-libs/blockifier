use num_bigint::BigInt;
use starknet_api::StarknetApiError;
use thiserror::Error;

/// Errors caused by converting different types.
#[derive(Error, Debug)]
pub enum ConversionError {
    /// Error converting a negative [`BigInt`](num_bigint::BigInt).
    #[error("The given BigInt, {}, is negative.", bigint)]
    NegativeBigInt { bigint: BigInt },

    /// A StarkNet API [`error`](`StarknetApiError`).
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
}
