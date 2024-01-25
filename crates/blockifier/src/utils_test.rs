use std::collections::HashMap;

use assert_matches::assert_matches;
use pretty_assertions::assert_eq;

use crate::transaction::errors::NumericConversionError;
use crate::utils::{check_non_zero, subtract_mappings};

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
fn test_check_non_zero() {
    check_non_zero(1, "").unwrap();
    assert_matches!(
        check_non_zero(0, "test"), Err(NumericConversionError::DivByZero { info }) if info == "test"
    );
    assert!(check_non_zero(0.0, "").is_err());
    assert!(check_non_zero(0 as f64, "").is_err());
    assert!(check_non_zero(((2_u128.pow(127) + 1) as f64) as u128 - 2_u128.pow(127), "").is_err());
}
