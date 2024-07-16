use std::fmt::Debug;
use std::sync::{Mutex, MutexGuard};

use crate::concurrency::TxIndex;

// This stract is used to abort the program if a
// panic ocurred in a place where it cannot be handled.
pub struct AbortGuard;

impl Drop for AbortGuard {
    fn drop(&mut self) {
        eprintln!("detected unexpected panic; aborting");
        ::std::process::abort();
    }
}

impl AbortGuard {
    pub fn release(self) {
        std::mem::forget(self);
    }
}

pub fn lock_mutex_in_array<T: Debug>(array: &[Mutex<T>], tx_index: TxIndex) -> MutexGuard<'_, T> {
    array[tx_index].lock().unwrap_or_else(|error| {
        panic!("Cell of transaction index {} is poisoned. Data: {:?}.", tx_index, *error.get_ref())
    })
}
