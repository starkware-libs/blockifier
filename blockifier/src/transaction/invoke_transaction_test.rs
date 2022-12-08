use starknet_api::core::Nonce;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{
    CallData, Fee, TransactionHash, TransactionSignature, TransactionVersion,
};

use crate::transaction::constants::ACCOUNT_CONTRACT_PATH;
use crate::transaction::invoke_transaction::InvokeTransaction;
use crate::transaction::objects::{CallInfo, ResourcesMapping, TransactionExecutionInfo};
use crate::transaction::transaction_errors::TransactionExecutionError;
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

#[test]
fn test_invoke_transaction() -> Result<(), TransactionExecutionError> {
    let (call_contract_calldata, invoke_transaction) = get_tested_valid_invoke_transaction();

    let execute_result = invoke_transaction.execute()?;
    assert_eq!(
        execute_result,
        TransactionExecutionInfo {
            // 'account_without_some_syscalls' simply returns the calldata it was given.
            call_info: Some(call_contract_calldata),
            actual_fee: Fee(1),
            ..TransactionExecutionInfo::default()
        }
    );

    Ok(())
}

#[test]
fn test_invoke_transaction_with_insufficient_fee() {
    let (_, mut invoke_transaction) = get_tested_valid_invoke_transaction();

    // Invalidate the invoke transaction.
    invoke_transaction.max_fee = Fee(0);
    assert!(matches!(
        invoke_transaction.execute().unwrap_err(),
        TransactionExecutionError::String(error) if error == "Actual fee exceeded max fee."
    ));
}

#[test]
fn test_invoke_transaction_with_invalid_version() {
    let (_, mut invoke_transaction) = get_tested_valid_invoke_transaction();

    // Currently, the only supported version is 1.
    // Note: there is no need to test for a negative version, as it cannot be constructed.
    for invalid_version_id in [0, 2] {
        let invalid_transaction_version = TransactionVersion(StarkHash::from(invalid_version_id));
        invoke_transaction.version = invalid_transaction_version;

        assert!(matches!(
            invoke_transaction.execute().unwrap_err(),
            TransactionExecutionError::String(error)
            if error == format!(
                "Transaction version {:?} is not supported. \
                Supported versions: [TransactionVersion(StarkFelt(\"\
                0x0000000000000000000000000000000000000000000000000000000000000001\"))].",
                invalid_transaction_version)
        ));
    }
}
