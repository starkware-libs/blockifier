use pretty_assertions::assert_eq;

use crate::concurrency::versioned_cell::VersionedCell;

#[test]
fn test_versioned_cell() {
    let initial_value = 14;
    let mut versioned_cell = VersionedCell::new(initial_value);

    // Read init value
    assert_eq!(versioned_cell.read(5), &initial_value);

    // Write to the versioned cell
    let version_2_value = 200;
    versioned_cell.write(2, version_2_value);

    assert_eq!(versioned_cell.read(1), &initial_value);
    assert_eq!(versioned_cell.read(5), &version_2_value);
    assert_eq!(versioned_cell.read(2), &version_2_value);

    // Write a new value
    let version_2_new_value = 201;
    versioned_cell.write(2, version_2_new_value);

    assert_eq!(versioned_cell.read(3), &version_2_new_value);
}
