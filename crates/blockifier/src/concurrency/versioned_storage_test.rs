use pretty_assertions::assert_eq;

use crate::concurrency::versioned_storage::{ReadCallback, VersionedStorage};

#[test]
fn test_versioned_storage() {
    let base_value_read_callback: Box<ReadCallback<u64, i32>> =
        Box::new(|cell_id| if cell_id == 100 { None } else { Some(31) });
    let mut storage = VersionedStorage::new(base_value_read_callback);

    // Read an uninitialized cell.
    let value = storage.read(1, 1);
    assert!(value.is_ok());
    assert_eq!(value.unwrap(), &31_i32);

    // Write.
    storage.write(1, 1, 42);
    let value = storage.read(1, 123);
    assert!(value.is_ok());
    assert_eq!(value.unwrap(), &42_i32);

    // Read initial value.
    let value = storage.read(5, 1);
    assert!(value.is_ok());
    assert_eq!(value.unwrap(), &31_i32);

    // Read from the past.
    storage.write(10, 2, 78);
    let value = storage.read(10, 1);
    assert!(value.is_ok());
    assert_eq!(value.unwrap(), &31_i32);

    let value = storage.read(10, 2);
    assert!(value.is_ok());
    assert_eq!(value.unwrap(), &78_i32);

    // Read uninitialized cell.
    let value = storage.read(100, 1);
    assert!(value.is_err());

    // Write to uninitialized cell.
    storage.write(100, 20, 194);

    // Test the write.
    let value = storage.read(100, 50);
    assert!(value.is_ok());
    assert_eq!(value.unwrap(), &194_i32);

    let value = storage.read(100, 10);
    assert!(value.is_err());
}
