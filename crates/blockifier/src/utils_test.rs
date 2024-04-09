use std::collections::HashMap;

use pretty_assertions::assert_eq;

use crate::utils::{strict_subtract_mappings, subtract_mappings, STRICT_SUBTRACT_MAPPING_ERROR};

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
fn test_strict_subtract_mappings_good() {
    let not_empty = HashMap::from([("foo", "bar")]);
    let empty = HashMap::default();

    assert_eq!(empty, strict_subtract_mappings(&empty, &not_empty));

    let map1 = HashMap::from([("green", 2), ("blue", 3)]);
    let map2 = HashMap::from([("red", 1), ("green", 2), ("blue", 4)]);

    let expected = HashMap::from([("blue", 3)]);
    assert_eq!(expected, strict_subtract_mappings(&map1, &map2));
}

#[test]
fn test_strict_subtract_mappings_bad() {
    let not_empty = HashMap::from([("foo", "bar")]);
    let empty = HashMap::default();
    let result = std::panic::catch_unwind(|| strict_subtract_mappings(&not_empty, &empty));
    assert_eq!(
        result.err().unwrap().downcast_ref::<String>().unwrap(),
        STRICT_SUBTRACT_MAPPING_ERROR
    );

    let map1 = HashMap::from([("yellow", 5), ("green", 2), ("blue", 3)]);
    let map2 = HashMap::from([("green", 2), ("blue", 4)]);

    let result = std::panic::catch_unwind(|| strict_subtract_mappings(&map1, &map2));
    assert_eq!(
        result.err().unwrap().downcast_ref::<String>().unwrap(),
        STRICT_SUBTRACT_MAPPING_ERROR
    );

    let map1 = HashMap::from([("yellow", 5), ("green", 2), ("blue", 3)]);
    let map2 = HashMap::from([("red", 1), ("green", 2), ("blue", 4)]);

    let result = std::panic::catch_unwind(|| strict_subtract_mappings(&map1, &map2));
    assert_eq!(
        result.err().unwrap().downcast_ref::<String>().unwrap(),
        STRICT_SUBTRACT_MAPPING_ERROR
    );
}
