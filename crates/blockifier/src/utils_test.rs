use std::collections::HashMap;

use assert_matches::assert_matches;
use pretty_assertions::assert_eq;

use crate::transaction::errors::NumericError;
use crate::utils::{checked_div, checked_div_f64, subtract_mappings};

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
fn test_checked_div() {
    assert_eq!(checked_div(10, 2).unwrap(), 5);
    assert_eq!(checked_div_f64(10.0, 2.0).unwrap(), 5.0);
    assert_matches!(
        checked_div(10, 0), Err(NumericError::CheckedDiv { numerator, denominator })
        if numerator == "10" && denominator == "0"
    );
    assert_matches!(
        checked_div_f64(10.0, 0.0), Err(NumericError::CheckedDivF64 { numerator, denominator })
        if numerator == 10.0 && denominator == 0.0
    );
    assert_matches!(
        checked_div_f64(0.0, 0.0), Err(NumericError::CheckedDivF64 { numerator, denominator })
        if numerator == 0.0 && denominator == 0.0
    );
}
