use std::fmt::Debug;
use std::sync::{Mutex, MutexGuard};

use crate::concurrency::TxIndex;

pub fn lock_mutex_in_array<T: Debug>(array: &[Mutex<T>], tx_index: TxIndex) -> MutexGuard<'_, T> {
    array[tx_index].lock().unwrap_or_else(|error| {
        panic!("Cell of transaction index {} is poisoned. Data: {:?}.", tx_index, *error.get_ref())
    })
}
