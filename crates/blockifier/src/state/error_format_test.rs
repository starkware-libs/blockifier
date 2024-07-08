use starknet_api::core::ClassHash;
use starknet_types_core::felt::Felt;

use crate::state::errors::StateError;

#[test]
fn test_error_undeclared_class_hash_format() {
    let error = StateError::UndeclaredClassHash(ClassHash(Felt::TWO));
    assert_eq!(
        error.to_string(),
        "Class with hash 0x0000000000000000000000000000000000000000000000000000000000000002 is \
         not declared."
    );
}
