use std::collections::HashMap;

use pretty_assertions::assert_eq;

use crate::utils::{bit_reverse_vec, subtract_mappings};

#[test]
fn test_subtract_mappings() {
    let not_empty = HashMap::from([("foo", "bar")]);
    let empty = HashMap::default();

    assert_eq!(empty, subtract_mappings(&empty, &not_empty));
    assert_eq!(not_empty, subtract_mappings(&not_empty, &empty));

    let map1 = HashMap::from([("red", 1), ("green", 2), ("blue", 3)]);
    let map2 = HashMap::from([("yellow", 1), ("green", 2), ("blue", 4)]);

    let expected = HashMap::from([("red", 1), ("blue", 3)]);
    assert_eq!(expected, subtract_mappings(&map1, &map2));
}

#[test]
fn test_bit_reverse_vec() {
    let vec = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let log_domain_size = 3;
    let expected = vec![8, 12, 10, 14, 9, 13, 11, 15, 0, 4, 2, 6, 1, 5, 3, 7];
    let actual = bit_reverse_vec(&vec, log_domain_size);
    assert_eq!(actual, expected);
}
