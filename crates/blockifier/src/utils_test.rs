use std::collections::HashMap;

use pretty_assertions::assert_eq;

use crate::utils::{f64_into_u128, subtract_mappings, u128_from_usize, usize_into_f64};

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

    // Small loss error when converting to f64 shouldn't throw an error
    let loss_val_usize = 12676506002282294014; //2535301200456458436608
    let loss_val_u128 = u128_from_usize(loss_val_usize).unwrap();
    let loss_val_f64 = usize_into_f64(loss_val_usize);
    assert!(loss_val_f64.is_ok());
    // 53 mantissa bits should not contain an error
    let loss_val = f64_into_u128(loss_val_f64.unwrap()).unwrap();
    let loss_range = loss_val_u128 >> 53;
    assert!(loss_val.abs_diff(loss_val_u128) <= loss_range);

    // Negative tests, assert error thrown.
    assert!(f64_into_u128(-10.0).is_err());
    assert!(f64_into_u128(2.0_f64.powi(129)).is_err());
    // assert!(usize_into_f64((2 << 54) + 1).is_err());
}
