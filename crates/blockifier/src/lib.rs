#[cfg(feature = "jemalloc")]
// Override default allocator.
#[global_allocator]
pub static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

pub mod abi;
pub mod block;
pub mod context;
pub mod execution;
pub mod fee;
pub mod state;
#[cfg(any(feature = "testing", test))]
pub mod test_utils;
pub mod transaction;
pub mod utils;
pub mod versioned_constants;
