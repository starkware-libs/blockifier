use cairo_vm::Felt252;
use rstest::rstest;
use starknet_api::core::ClassHash;

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
