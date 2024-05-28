#[derive(Debug, Default, Clone)]
pub struct TransactionExecutorConfig {
    pub concurrency_config: ConcurrencyConfig,
}

#[derive(Debug, Clone)]
pub struct ConcurrencyConfig {
    pub enabled: bool,
    pub n_workers: usize,
    pub chunk_size: usize,
}

impl Default for ConcurrencyConfig {
    fn default() -> Self {
        // TODO(barak, 01/08/2024): Import the `n_workers` and the `chunk_size` from the concurrency
        // utils file once the `concurrency` module becomes an integral part of the crate and its
        // feature configuration is removed.
        Self { enabled: false, n_workers: 64, chunk_size: 4 }
    }
}
