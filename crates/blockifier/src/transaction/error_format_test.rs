use rstest::rstest;
use starknet_api::transaction::TransactionVersion;

use crate::transaction::errors::TransactionExecutionError;

#[rstest]
fn test_contract_class_version_mismatch_format() {
    let error = TransactionExecutionError::ContractClassVersionMismatch {
        declare_version: TransactionVersion::THREE,
        cairo_version: 12,
    };
    assert_eq!(
        error.to_string(),
        "Declare transaction version 3 must have a contract class of Cairo version 12."
    )
}
