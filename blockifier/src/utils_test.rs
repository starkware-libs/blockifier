use std::collections::HashMap;

use pretty_assertions::assert_eq;

use super::*;

#[test]
fn test_subtract_mappings() {
    let map1 =
        HashMap::from([("all", "same"), ("same key", "different value"), ("all", "different")]);
    let map2 = HashMap::from([
        ("all", "same"),
        ("same key", "different plumbus"),
        ("abolish", "coke-not-zero"),
    ]);

    let expected = HashMap::from([("same key", "different value"), ("all", "different")]);
    assert_eq!(expected, subtract_mappings(&map1, &map2));
}
