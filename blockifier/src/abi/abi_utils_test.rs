use num_bigint::BigUint;
use num_traits::Num;

use crate::abi::abi_utils::get_selector_from_name;
use crate::abi::constants::{
    DEFAULT_ENTRY_POINT_NAME, DEFAULT_ENTRY_POINT_SELECTOR, DEFAULT_L1_ENTRY_POINT_NAME,
    EXECUTE_ENTRY_POINT_NAME,
};
use crate::transaction::constants::EXECUTE_ENTRY_POINT_SELECTOR;

// The entrypoint selector corresponding to an "empty" entrypoint, i.e., '""'.
pub const EMPTY_ENTRY_POINT_SELECTOR: &str =
    "1d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

#[test]
fn test_get_selector_from_name() {
    assert_eq!(
        get_selector_from_name(DEFAULT_ENTRY_POINT_NAME),
        BigUint::from(DEFAULT_ENTRY_POINT_SELECTOR)
    );

    assert_eq!(
        get_selector_from_name(DEFAULT_L1_ENTRY_POINT_NAME),
        BigUint::from(DEFAULT_ENTRY_POINT_SELECTOR)
    );

    assert_eq!(
        get_selector_from_name(EXECUTE_ENTRY_POINT_NAME),
        // Note: The 'from_str_radix' requires the hexadecimal string to not start with '0x'.
        BigUint::from_str_radix(&EXECUTE_ENTRY_POINT_SELECTOR[2..], 16).unwrap()
    );

    assert_eq!(
        get_selector_from_name(""),
        // Note: The 'from_str_radix' requires the hexadecimal string to not start with '0x'.
        BigUint::from_str_radix(EMPTY_ENTRY_POINT_SELECTOR, 16).unwrap()
    );
}
