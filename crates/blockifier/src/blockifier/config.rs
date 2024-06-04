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
        Self { enabled: true, n_workers: 64, chunk_size: 4 }
    }
}
