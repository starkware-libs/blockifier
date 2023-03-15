#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

pub mod abi;
pub mod block_context;
pub mod execution;
pub mod fee;
pub mod state;
#[cfg(any(feature = "testing", test))]
pub mod test_utils;
pub mod transaction;
pub mod utils;

mod collections {
    #[cfg(feature = "std")]
    pub use std::collections::{HashMap, HashSet};

    #[cfg(not(feature = "std"))]
    pub use hashbrown::{HashMap, HashSet};
}
