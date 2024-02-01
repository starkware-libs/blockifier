use thiserror::Error;

#[derive(Debug, Error)]
pub enum BouncerError {
    #[error(
        "The batch remaining capapcity is too small for the transaction. parameter {}, weight {}, \
         accumulated_weight {}, max_weight {}",
        parameter,
        tx_weight,
        accumulated_weight,
        max_weight
    )]
    BatchFull { parameter: String, tx_weight: u64, accumulated_weight: u64, max_weight: u64 },
    #[error(transparent)]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error(
        "Transaction is too big to fit the batch, parameter {} weight {} is bigger than the \
         upper_bound {}",
        parameter,
        weight,
        max
    )]
    TransactionBiggerThanBatch { parameter: String, weight: u64, max: u64 },
}
