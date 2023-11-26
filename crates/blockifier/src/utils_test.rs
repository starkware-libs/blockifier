use std::collections::HashMap;

use indexmap::IndexMap;
use pretty_assertions::assert_eq;

use crate::utils::subtract_mappings;

#[test]
fn test_subtract_mappings() {
    let not_empty = HashMap::from([("foo", "bar")]);
    let empty = IndexMap::default();

    assert_eq!(empty, subtract_mappings(&empty, &not_empty));

    let not_empty = IndexMap::from([("foo", "bar")]);
    let empty = HashMap::default();
    assert_eq!(not_empty, subtract_mappings(&not_empty, &empty));

    let map1 = IndexMap::from([("red", 1), ("green", 2), ("blue", 3)]);
    let map2 = HashMap::from([("yellow", 1), ("green", 2), ("blue", 4)]);

    let expected = IndexMap::from([("red", 1), ("blue", 3)]);
    assert_eq!(expected, subtract_mappings(&map1, &map2));
}
