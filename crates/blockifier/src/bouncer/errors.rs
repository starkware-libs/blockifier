use thiserror::Error;

use super::counting_bouncer::BouncerWeights;

#[derive(Debug, Error)]
pub enum BouncerError {
    #[error(
        "The batch remaining capapcity is too small for the transaction. accumulated_weights \
         {:?}, max_weights {:?}",
        tx_weights,
        accumulated_weights,
        max_weights
    )]
    BatchFull { accumulated_weights: BouncerWeights, max_weights: BouncerWeights },
    #[error(transparent)]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error(
        "Transaction is too big to fit the batch, tx_weights {:?}, max_weights {:?}",
        tx_weights,
        max_weights
    )]
    TransactionBiggerThanBatch { tx_weights: BouncerWeights, max_weights: BouncerWeights },
}
