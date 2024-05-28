use crate::concurrency::utils::{DEFAULT_CHUNK_SIZE, DEFAULT_N_WORKERS};

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
        Self { enabled: false, n_workers: DEFAULT_N_WORKERS, chunk_size: DEFAULT_CHUNK_SIZE }
    }
}
