#[derive(Debug, Default, Clone)]
pub struct TransactionExecutorConfig {
    pub concurrency_config: ConcurrencyConfig,
}
impl TransactionExecutorConfig {
    #[cfg(any(test, feature = "testing"))]
    pub fn create_for_testing() -> Self {
        Self { concurrency_config: ConcurrencyConfig::create_for_testing() }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ConcurrencyConfig {
    pub enabled: bool,
    pub n_workers: usize,
    pub chunk_size: usize,
}
#[cfg(all(any(test, feature = "testing"), not(feature = "concurrency")))]
impl ConcurrencyConfig {
    pub fn create_for_testing() -> Self {
        Self { enabled: false, n_workers: 0, chunk_size: 0 }
    }
}

#[cfg(all(any(test, feature = "testing"), feature = "concurrency"))]
impl ConcurrencyConfig {
    pub fn create_for_testing() -> Self {
        Self { enabled: true, n_workers: 4, chunk_size: 64 }
    }
}
