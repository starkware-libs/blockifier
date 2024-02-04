use pretty_assertions::assert_eq;

use crate::concurrency::versioned_storage::{ReadCallback, VersionedStorage};

#[test]
fn test_versioned_storage() {
    let base_value_read_callback: Box<ReadCallback<u64, i32>> = Box::new(|_cell_id| Ok(31));
    let mut storage = VersionedStorage::new(base_value_read_callback);

    // Read an uninitialized cell.
    let value = storage.read(1, 1);
    assert_eq!(value, 31);

    // Write.
    storage.write(1, 1, 42);
    let value = storage.read(1, 2);
    assert_eq!(value, 42);

    // Read initial value.
    let value = storage.read(5, 1);
    assert_eq!(value, 31);

    // Read from the past.
    storage.write(10, 1, 78);
    let value = storage.read(10, 1);
    assert_eq!(value, 78);
}
