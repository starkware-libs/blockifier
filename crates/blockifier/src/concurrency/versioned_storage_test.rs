use pretty_assertions::assert_eq;

use crate::concurrency::versioned_storage::VersionedStorage;

#[test]
fn test_versioned_storage() {
    let mut storage = VersionedStorage::default();

    // Read an uninitialized cell.
    let value = storage.read(0, 1);
    assert!(value.is_none());

    // Set initial values.
    storage.set_initial_value(1, 31);
    storage.set_initial_value(5, 31);
    storage.set_initial_value(10, 31);

    // Write.
    storage.write(1, 1, 42);
    assert_eq!(storage.read(123, 1).unwrap(), 42);

    // Read initial value.
    assert_eq!(storage.read(1, 5).unwrap(), 31);

    // Read from the past.
    storage.write(2, 10, 78);
    assert_eq!(storage.read(1, 10).unwrap(), 31);
    // Ignore the value written by the current transaction.
    assert_eq!(storage.read(2, 10).unwrap(), 31);

    // Read uninitialized cell.
    assert!(storage.read(1, 100).is_none());

    // Write to uninitialized cell.
    storage.write(20, 100, 194);

    // Test the write.
    assert_eq!(storage.read(50, 100).unwrap(), 194);
}
