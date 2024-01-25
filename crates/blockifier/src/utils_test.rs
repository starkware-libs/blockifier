use std::collections::HashMap;

use pretty_assertions::assert_eq;

use crate::utils::{f64_into_u128, subtract_mappings, usize_into_f64};

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
fn test_usize_f64_u128_conversions() {
    // Positive tests.
    let val_usize: usize = 10;
    let val_f64: f64 = 10.0;
    assert_eq!(usize_into_f64(val_usize).unwrap(), val_f64);
    assert_eq!(f64_into_u128(val_f64).unwrap(), u128::try_from(val_usize).unwrap());

    // Negative tests, assert error thrown.
    let negative_val: f64 = -10.0;
    assert!(f64_into_u128(negative_val).is_err());
    let too_big_val: f64 = 2.0_f64.powi(129);
    assert!(f64_into_u128(too_big_val).is_err());
    let loss_conversion_val: usize = (2 << 54) + 1;
    assert!(usize_into_f64(loss_conversion_val).is_err());
}
