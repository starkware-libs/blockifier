use cairo_vm::Felt252;
use rstest::rstest;
use starknet_api::core::{ClassHash, ContractAddress};

use crate::state::errors::StateError;

#[rstest]
fn test_error_undeclared_class_hash_forrmat() {
    let error = StateError::UndeclaredClassHash(ClassHash(Felt252::from(2)));
    assert_eq!(
        error.to_string(),
        "Class with hash 0x0000000000000000000000000000000000000000000000000000000000000002 is \
         not declared."
    );
}

#[rstest]
fn test_error_unavailable_contract_address_format() {
    let error = StateError::UnavailableContractAddress(ContractAddress::from(10_u128));
    assert_eq!(
        error.to_string(),
        "Requested 0x000000000000000000000000000000000000000000000000000000000000000a is \
         unavailable for deployment."
    );
}
