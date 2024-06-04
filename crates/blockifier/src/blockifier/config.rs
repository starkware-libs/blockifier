#[derive(Debug, Default, Clone)]
pub struct TransactionExecutorConfig {
    pub concurrency_config: ConcurrencyConfig,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "concurrency"), derive(Default))]
pub struct ConcurrencyConfig {
    pub enabled: bool,
    pub n_workers: usize,
    pub chunk_size: usize,
}

#[cfg(feature = "concurrency")]
impl Default for ConcurrencyConfig {
    fn default() -> Self {
        Self { enabled: true, n_workers: 4, chunk_size: 64 }
    }
}
