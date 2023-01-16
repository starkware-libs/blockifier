use starknet_api::core::EntryPointSelector;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;

use crate::abi::abi_utils::get_selector;
use crate::abi::constants::{
    DEFAULT_ENTRY_POINT_NAME, DEFAULT_ENTRY_POINT_SELECTOR, DEFAULT_L1_ENTRY_POINT_NAME,
};
use crate::transaction::constants::EXECUTE_ENTRY_POINT_NAME;

#[test]
fn test_get_selector_from_name() {
    // Test default EP.
    let expected_default_selector = EntryPointSelector(stark_felt!(DEFAULT_ENTRY_POINT_SELECTOR));
    assert_eq!(get_selector(DEFAULT_ENTRY_POINT_NAME), expected_default_selector);
    assert_eq!(get_selector(DEFAULT_L1_ENTRY_POINT_NAME), expected_default_selector);

    // Test execute EP.
    let expected_execute_selector =
        "0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad";
    let expected_execute_selector = EntryPointSelector(stark_felt!(expected_execute_selector));
    assert_eq!(get_selector(EXECUTE_ENTRY_POINT_NAME), expected_execute_selector);

    // Test empty EP.
    let expected_empty_selector =
        "0x1d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    let expected_empty_selector = EntryPointSelector(stark_felt!(expected_empty_selector));
    assert_eq!(get_selector(""), expected_empty_selector);
}
