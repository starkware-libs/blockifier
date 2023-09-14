use thiserror::Error;

#[derive(Debug, Error)]
pub enum GasPriceQueryError {
    #[error("No pool states provided.")]
    NoPoolStatesError,
}
