use pretty_assertions::assert_eq;

use crate::concurrency::versioned_storage::VersionedStorage;

#[test]
fn test_versioned_storage() {
    let mut storage = VersionedStorage::new();

    // Read an uninitialized cell.
    let value = storage.read(1, 1);
    assert!(value.is_none());

    storage.set_initial_value(1, 31_i32);
    storage.set_initial_value(5, 31_i32);
    storage.set_initial_value(10, 31_i32);

    // Write.
    storage.write(1, 1, 42);
    let value = storage.read(1, 123);
    assert_eq!(value.unwrap(), 42_i32);

    // Read initial value.
    let value = storage.read(5, 1);
    assert_eq!(value.unwrap(), 31_i32);

    // Read from the past.
    storage.write(10, 2, 78);
    let value = storage.read(10, 1);
    assert_eq!(value.unwrap(), 31_i32);

    let value = storage.read(10, 2);
    assert_eq!(value.unwrap(), 78_i32);

    // Read uninitialized cell.
    let value = storage.read(100, 1);
    assert!(value.is_none());

    // Write to uninitialized cell.
    storage.write(100, 20, 194);

    // Test the write.
    let value = storage.read(100, 50);
    assert_eq!(value.unwrap(), 194_i32);

    let value = storage.read(100, 10);
    assert!(value.is_none());
}
