use starknet_api::core::Nonce;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{
    CallData, Fee, TransactionHash, TransactionSignature, TransactionVersion,
};

use crate::transaction::constants::ACCOUNT_CONTRACT_PATH;
use crate::transaction::errors::{FeeTransferError, TransactionExecutionError};
use crate::transaction::invoke_transaction::InvokeTransaction;
use crate::transaction::objects::TransactionExecutionInfo;
use crate::transaction::ExecuteTransaction;

fn get_tested_valid_invoke_transaction() -> (Vec<StarkHash>, InvokeTransaction) {
    // The calldata given to the contract address selector, specified in the invoke transaction
    // calldata.
    let call_contract_calldata = vec![StarkFelt::from(2)];
    let calldata = [
        vec![
            // Dummy contract address.
            StarkFelt::default(),
            // Dummy selector.
            StarkFelt::default(),
            // calldata_len.
            StarkFelt::from(call_contract_calldata.len() as u64),
        ],
        // calldata.
        call_contract_calldata.clone(),
    ]
    .concat();

    let invoke_transaction = InvokeTransaction {
        transaction_hash: TransactionHash(StarkHash::default()),
        max_fee: Fee(1),
        version: TransactionVersion(StarkFelt::from(1)),
        signature: TransactionSignature(vec![StarkHash::default()]),
        nonce: Nonce::default(),
        contract_file_path: ACCOUNT_CONTRACT_PATH.to_string(),
        entry_point_selector: None,
        calldata: CallData(calldata),
    };

    (call_contract_calldata, invoke_transaction)
}

fn get_tested_actual_fee() -> Fee {
    Fee(1)
}

#[test]
fn test_invoke_transaction() -> Result<(), TransactionExecutionError> {
    let (call_contract_calldata, invoke_transaction) = get_tested_valid_invoke_transaction();

    let execute_result = invoke_transaction.execute()?;
    assert_eq!(
        execute_result,
        TransactionExecutionInfo {
            // 'account_without_some_syscalls' simply returns the calldata it was given.
            execute_info: Some(call_contract_calldata),
            actual_fee: get_tested_actual_fee(),
            ..TransactionExecutionInfo::default()
        }
    );

    Ok(())
}

#[test]
fn test_invoke_transaction_with_insufficient_fee() {
    let (_, mut invoke_transaction) = get_tested_valid_invoke_transaction();
    let expected_actual_fee = get_tested_actual_fee();

    // Invalidate the invoke transaction.
    invoke_transaction.max_fee = Fee(0);
    let execution_error = invoke_transaction.execute().unwrap_err();

    // Test error message.
    assert_eq!(
        execution_error.to_string(),
        format!(
            "Actual fee ({:?}) exceeded max fee ({:?}).",
            expected_actual_fee, invoke_transaction.max_fee
        )
    );

    // Test error type.
    assert!(matches!(
        execution_error,
        TransactionExecutionError::FeeTransferError(error)
        if error ==  FeeTransferError::MaxFeeExceeded {
            max_fee: invoke_transaction.max_fee,
            actual_fee: expected_actual_fee,
        }
    ));
}

#[test]
fn test_invoke_transaction_with_invalid_version() {
    let (_, mut invoke_transaction) = get_tested_valid_invoke_transaction();
    let expected_supported_versions = vec![TransactionVersion(StarkFelt::from(1))];

    // Currently, the only supported version is 1.
    // Note: there is no need to test for a negative version, as it cannot be constructed.
    for invalid_version_id in [0, 2] {
        let invalid_transaction_version = TransactionVersion(StarkHash::from(invalid_version_id));
        invoke_transaction.version = invalid_transaction_version;
        let execution_error = invoke_transaction.execute().unwrap_err();

        // Test error message.
        assert_eq!(
            execution_error.to_string(),
            format!(
                "Transaction version {:?} is not supported. Supported versions: {:?}.",
                invalid_transaction_version, &expected_supported_versions
            )
        );

        // Test error type.
        assert!(matches!(
            execution_error,
            TransactionExecutionError::InvalidTransactionVersion {
                transaction_version,
                supported_versions,
            }
            if (transaction_version, &supported_versions) == (
                invalid_transaction_version,
                &expected_supported_versions
            )
        ));
    }
}
