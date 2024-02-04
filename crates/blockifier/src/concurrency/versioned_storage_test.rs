use pretty_assertions::assert_eq;

use crate::concurrency::versioned_storage::CellId;
use crate::concurrency::versioned_storage::VersionedStorage;
use crate::concurrency::versioned_storage::ReadCallback;

#[test]
fn test_versioned_cell() {
    let base_value_read_callback: Box<ReadCallback<CellId, i32>> = Box::new(|_cell_id| Some(31));
    let mut storage = VersionedStorage::new(base_value_read_callback);

    let value = storage.read(1, 1);
    assert_eq!(value, &31);

    storage.write(1, 1, 42);
    let value = storage.read(1, 2);
    assert_eq!(value, &42);

    let value = storage.read(5, 1);
    assert_eq!(value, &31);

    storage.write(10, 1, 78);
    let value = storage.read(10, 1);
    assert_eq!(value, &78);
}
