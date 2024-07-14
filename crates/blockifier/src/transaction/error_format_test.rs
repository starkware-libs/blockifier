use starknet_api::transaction::TransactionVersion;

use crate::transaction::errors::TransactionExecutionError;

#[test]
fn test_contract_class_version_mismatch() {
    let error = TransactionExecutionError::ContractClassVersionMismatch {
        declare_version: TransactionVersion::ONE,
        cairo_version: 2,
    };
    assert_eq!(
        error.to_string(),
        "Declare transaction version 1 must have a contract class of Cairo version 2."
    );
}
