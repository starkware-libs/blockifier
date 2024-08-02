// This crate assumes conversion of usize to u128 never fails. Assuming index type is equal in bit
// length to pointer type ([not necessarily true](https://github.com/rust-lang/rust/issues/65473),
// but it is a reasonable assumption for now), this attribute protects against potential overflow
// when converting usize to u128.
#![cfg(any(
    target_pointer_width = "16",
    target_pointer_width = "32",
    target_pointer_width = "64",
    target_pointer_width = "128"
))]

#[cfg(feature = "jemalloc")]
// Override default allocator.
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

pub mod abi;
pub mod blockifier;
pub mod bouncer;
#[cfg(feature = "concurrency")]
pub mod concurrency;
pub mod context;
pub mod execution;
pub mod fee;
pub mod state;
#[cfg(any(feature = "testing", test))]
pub mod test_utils;
pub mod transaction;
pub mod utils;
pub mod versioned_constants;
