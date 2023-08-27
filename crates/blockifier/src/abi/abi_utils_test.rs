use assert_matches::assert_matches;
use cairo_felt::Felt252;
use num_bigint::BigUint;
use starknet_api::core::EntryPointSelector;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants as abi_constants;
use crate::abi::sierra_types::{felt_to_u128, SierraTypeError};
use crate::transaction::constants as transaction_constants;

#[test]
fn test_selector_from_name() {
    // Test default EP.
    let expected_default_selector =
        EntryPointSelector(stark_felt!(abi_constants::DEFAULT_ENTRY_POINT_SELECTOR));
    assert_eq!(
        selector_from_name(abi_constants::DEFAULT_ENTRY_POINT_NAME),
        expected_default_selector
    );
    assert_eq!(
        selector_from_name(abi_constants::DEFAULT_L1_ENTRY_POINT_NAME),
        expected_default_selector
    );

    // Test execute EP.
    let expected_execute_selector =
        "0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad";
    let expected_execute_selector = EntryPointSelector(stark_felt!(expected_execute_selector));
    assert_eq!(
        selector_from_name(transaction_constants::EXECUTE_ENTRY_POINT_NAME),
        expected_execute_selector
    );

    // Test empty EP.
    let expected_empty_selector =
        "0x1d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    let expected_empty_selector = EntryPointSelector(stark_felt!(expected_empty_selector));
    assert_eq!(selector_from_name(""), expected_empty_selector);
}

#[test]
fn test_value_too_large_for_type() {
    // Happy flow.
    let n = 1991_u128;
    let n_as_felt = Felt252::from(n);
    felt_to_u128(&n_as_felt).unwrap();

    // Value too large for type.
    let overflowed_u128: BigUint = BigUint::from(1_u8) << 128;
    let overflowed_u128_as_felt = Felt252::from(overflowed_u128);
    let error = felt_to_u128(&overflowed_u128_as_felt).unwrap_err();
    assert_matches!(
        error,
        SierraTypeError::ValueTooLargeForType { val: expected_val, ty: "u128"}
        if expected_val == overflowed_u128_as_felt
    )
}
