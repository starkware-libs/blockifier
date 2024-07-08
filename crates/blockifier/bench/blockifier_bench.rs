//! Benchmark module for the blockifier crate. It provides functionalities to benchmark
//! various aspects related to transferring between accounts, including preparation
//! and execution of transfers.
//!
//! The main benchmark function is `transfers_benchmark`, which measures the performance
//! of transfers between randomly created accounts, which are iterated over round-robin.
//!
//! Run the benchmarks using `cargo bench --bench blockifier_bench`.

use blockifier::test_utils::transfers_generator::{RecipientGeneratorType, TransfersGenerator};
use criterion::{criterion_group, criterion_main, Criterion};

pub fn transfers_benchmark(c: &mut Criterion) {
    let mut transfers_generator = TransfersGenerator::new(RecipientGeneratorType::Random);
    // Create a benchmark group called "transfers", which iterates over the accounts round-robin
    // and performs transfers.
    c.bench_function("transfers", |benchmark| {
        benchmark.iter(|| {
            transfers_generator.execute_transfers_stream();
        })
    });
}

criterion_group!(benches, transfers_benchmark);
criterion_main!(benches);
