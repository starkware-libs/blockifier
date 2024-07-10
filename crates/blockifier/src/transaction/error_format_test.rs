use rstest::rstest;
use starknet_api::core::ClassHash;
use starknet_api::hash::StarkHash;
use starknet_api::transaction::TransactionVersion;

use crate::transaction::errors::TransactionExecutionError;

#[rstest]
fn test_contract_class_version_mismatch_format() {
    let error = TransactionExecutionError::ContractClassVersionMismatch {
        declare_version: TransactionVersion::ONE,
        cairo_version: 2,
    };
    assert_eq!(
        error.to_string(),
        "Declare transaction version 1 must have a contract class of Cairo version 2."
    );
}

#[rstest]
fn test_declare_transaction_error_format() {
    let error = TransactionExecutionError::DeclareTransactionError {
        class_hash: ClassHash(StarkHash::THREE),
    };
    assert_eq!(
        error.to_string(),
        "Class with hash 0x0000000000000000000000000000000000000000000000000000000000000003 is \
         already declared."
    );
}

#[rstest]
fn test_invalid_version_format() {
    let error = TransactionExecutionError::InvalidVersion {
        version: TransactionVersion::THREE,
        allowed_versions: vec![TransactionVersion::ONE, TransactionVersion::TWO],
    };
    assert_eq!(
        error.to_string(),
        "Transaction version 0x3 is not supported. Supported versions: [0x1, 0x2]."
    );
}
