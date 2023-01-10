use starknet_api::core::EntryPointSelector;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;

use crate::abi::abi_utils::get_selector_from_name;
use crate::abi::constants::{
    DEFAULT_ENTRY_POINT_NAME, DEFAULT_ENTRY_POINT_SELECTOR, DEFAULT_L1_ENTRY_POINT_NAME,
};
use crate::transaction::constants::EXECUTE_ENTRY_POINT_NAME;

// The entry point selector corresponding to an "empty" entry point, i.e., '""'.
const EMPTY_ENTRY_POINT_SELECTOR: &str =
    "0x1d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

// The entry point selector corresponding to the execute entry point.
const EXECUTE_ENTRY_POINT_SELECTOR: &str =
    "0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad";

#[test]
fn test_get_selector_from_name() {
    assert_eq!(
        get_selector_from_name(DEFAULT_ENTRY_POINT_NAME),
        EntryPointSelector(stark_felt!(DEFAULT_ENTRY_POINT_SELECTOR))
    );

    assert_eq!(
        get_selector_from_name(DEFAULT_L1_ENTRY_POINT_NAME),
        EntryPointSelector(stark_felt!(DEFAULT_ENTRY_POINT_SELECTOR))
    );

    assert_eq!(
        get_selector_from_name(EXECUTE_ENTRY_POINT_NAME),
        EntryPointSelector(stark_felt!(EXECUTE_ENTRY_POINT_SELECTOR))
    );

    assert_eq!(
        get_selector_from_name(""),
        EntryPointSelector(stark_felt!(EMPTY_ENTRY_POINT_SELECTOR))
    );
}
