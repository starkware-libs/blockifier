//! Benchmark module for the blockifier crate. It provides functionalities to benchmark
//! various aspects related to transferring between accounts, including preparation
//! and execution of transfers.
//!
//! The main benchmark function is `transfers_benchmark`, which measures the performance
//! of transfers between randomly created accounts, which are iterated over round-robin.
//!
//! Run the benchmarks using `cargo bench --bench blockifier_bench`.

use blockifier::test_utils::transfers_generator::{
    IndexIteratorType, TransfersGenerator, TransfersGeneratorConfig,
};
use criterion::{criterion_group, criterion_main, Criterion};

const RANDOMIZATION_SEED: u64 = 0;

pub fn transfers_benchmark(c: &mut Criterion) {
    let transfers_generator_config = TransfersGeneratorConfig {
        recipient_iterator_type: IndexIteratorType::Random(RANDOMIZATION_SEED),
        ..Default::default()
    };
    let mut transfers_generator = TransfersGenerator::new(transfers_generator_config);
    // Create a benchmark group called "transfers", which iterates over the accounts round-robin
    // and performs transfers.
    c.bench_function("transfers", |benchmark| {
        benchmark.iter(|| {
            transfers_generator.execute_transfers();
        })
    });
}

criterion_group!(benches, transfers_benchmark);
criterion_main!(benches);
