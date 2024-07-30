use std::fmt::Debug;
use std::sync::{Mutex, MutexGuard};

use crate::concurrency::TxIndex;

// This struct is used to abort the program if a panic occurred in a place where it could not be
// handled.
pub struct AbortIfPanic;

impl Drop for AbortIfPanic {
    fn drop(&mut self) {
        eprintln!("detected unexpected panic; aborting");
        std::process::abort();
    }
}

impl AbortIfPanic {
    pub fn release(self) {
        std::mem::forget(self);
    }
}

pub fn lock_mutex_in_array<T: Debug>(array: &[Mutex<T>], tx_index: TxIndex) -> MutexGuard<'_, T> {
    array[tx_index].lock().unwrap_or_else(|error| {
        panic!("Cell of transaction index {} is poisoned. Data: {:?}.", tx_index, *error.get_ref())
    })
}
