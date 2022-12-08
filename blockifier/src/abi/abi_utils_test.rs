use starknet_api::core::EntryPointSelector;
use starknet_api::hash::StarkHash;
use starknet_api::shash;

use crate::abi::abi_utils::get_selector_from_name;
use crate::abi::constants::{
    DEFAULT_ENTRY_POINT_NAME, DEFAULT_ENTRY_POINT_SELECTOR, DEFAULT_L1_ENTRY_POINT_NAME,
    EXECUTE_ENTRY_POINT_NAME,
};
use crate::transaction::constants::EXECUTE_ENTRY_POINT_SELECTOR;

// The entry point selector corresponding to an "empty" entry point, i.e., '""'.
pub const EMPTY_ENTRY_POINT_SELECTOR: &str =
    "0x1d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

#[test]
fn test_get_selector_from_name() {
    assert_eq!(
        get_selector_from_name(DEFAULT_ENTRY_POINT_NAME),
        EntryPointSelector(shash!(DEFAULT_ENTRY_POINT_SELECTOR))
    );

    assert_eq!(
        get_selector_from_name(DEFAULT_L1_ENTRY_POINT_NAME),
        EntryPointSelector(shash!(DEFAULT_ENTRY_POINT_SELECTOR))
    );

    assert_eq!(
        get_selector_from_name(EXECUTE_ENTRY_POINT_NAME),
        EntryPointSelector(shash!(EXECUTE_ENTRY_POINT_SELECTOR))
    );

    assert_eq!(get_selector_from_name(""), EntryPointSelector(shash!(EMPTY_ENTRY_POINT_SELECTOR)));
}
