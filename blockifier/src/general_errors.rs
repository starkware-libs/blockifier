use num_bigint::BigInt;
use starknet_api::StarknetApiError;
use thiserror::Error;

/// Errors caused by converting different types.
#[derive(Error, Debug)]
pub enum ConversionError {
    #[error("The given BigInt, {0}, is negative.")]
    NegativeBigIntToFelt(BigInt),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
}
