use thiserror::Error;

#[derive(Debug, Error)]
pub enum StrkGasPriceCalcError {
    #[error("No pool states provided.")]
    NoPoolStatesError,
}
