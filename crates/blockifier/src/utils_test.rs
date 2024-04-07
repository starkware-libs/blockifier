use std::collections::HashMap;

use pretty_assertions::assert_eq;

use crate::utils::{subtract_mappings, u128_div_ceil};

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
fn test_u128_div_ceil() {
    assert_eq!(1, u128_div_ceil(1, 1));
    assert_eq!(1, u128_div_ceil(1, 2));
    assert_eq!(14, u128_div_ceil(27, 2));
    assert_eq!(14, u128_div_ceil(28, 2));
}
