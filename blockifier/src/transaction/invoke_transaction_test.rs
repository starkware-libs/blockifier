use pretty_assertions::assert_eq;
use starknet_api::core::Nonce;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{
    CallData, Fee, TransactionHash, TransactionSignature, TransactionVersion,
};

use crate::cached_state::{CachedState, DictStateReader};
use crate::execution::entry_point::{CallExecution, CallInfo};
use crate::transaction::constants::ACCOUNT_CONTRACT_PATH;
use crate::transaction::errors::{FeeTransferError, TransactionExecutionError};
use crate::transaction::invoke_transaction::InvokeTransaction;
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionInfo};
use crate::transaction::ExecuteTransaction;

fn get_tested_valid_invoke_tx() -> (Vec<StarkHash>, InvokeTransaction) {
    // The calldata given to the contract address selector, specified in the invoke transaction
    // calldata.
    let call_contract_calldata = vec![StarkFelt::from(2)];
    let mut calldata = vec![
        // Dummy contract address.
        StarkFelt::default(),
        // Dummy selector.
        StarkFelt::default(),
        // calldata_len.
        StarkFelt::from(call_contract_calldata.len() as u64),
    ];
    // Add the `call_contract_calldata` as calldata.
    calldata.extend_from_slice(&call_contract_calldata);

    let invoke_tx = InvokeTransaction {
        transaction_hash: TransactionHash(StarkHash::default()),
        max_fee: Fee(1),
        version: TransactionVersion(StarkFelt::from(1)),
        signature: TransactionSignature(vec![StarkHash::default()]),
        nonce: Nonce::default(),
        contract_file_path: ACCOUNT_CONTRACT_PATH.to_string(),
        entry_point_selector: None,
        calldata: CallData(calldata),
    };

    (call_contract_calldata, invoke_tx)
}

fn get_tested_actual_fee() -> Fee {
    Fee(1)
}

#[test]
fn test_invoke_tx() -> Result<(), TransactionExecutionError> {
    let state: CachedState<DictStateReader> = CachedState::default();
    let (call_contract_calldata, invoke_tx) = get_tested_valid_invoke_tx();

    let execute_result = invoke_tx.execute(state)?;

    // TODO(Adi, 20/12/2022): Replace the following `matches!` assertions with a single `assert_eq`
    // assertion and test the whole CallInfo object.
    assert!(matches!(
        &execute_result,
        TransactionExecutionInfo {
            execute_info:_, actual_fee, validate_info: _, fee_transfer_info, actual_resources
        }
        if (actual_fee, fee_transfer_info, actual_resources) == (
            &get_tested_actual_fee(), &CallInfo::default(), &ResourcesMapping::default())
    ));

    assert!(matches!(
        &execute_result.execute_info,
        Some(CallInfo { call: _, execution, inner_calls })
        // 'account_without_some_syscalls' simply returns the calldata it was given.
        if (execution, inner_calls) == (&CallExecution{retdata: call_contract_calldata}, &vec![])
    ));

    assert!(matches!(
        &execute_result.validate_info,
        CallInfo { call: _, execution, inner_calls }
        // 'account_without_some_syscalls' has a trivial `validate` function.
        if (execution, inner_calls) == (&CallExecution{retdata: vec![]}, &vec![])
    ));

    Ok(())
}

#[test]
fn test_invoke_tx_with_insufficient_fee() {
    let state: CachedState<DictStateReader> = CachedState::default();
    let (_, mut invoke_tx) = get_tested_valid_invoke_tx();
    let expected_actual_fee = get_tested_actual_fee();

    // Invalidate the invoke transaction.
    invoke_tx.max_fee = Fee(0);
    let execution_error = invoke_tx.execute(state).unwrap_err();

    // Test error message.
    assert_eq!(
        execution_error.to_string(),
        format!(
            "Actual fee ({:?}) exceeded max fee ({:?}).",
            expected_actual_fee, invoke_tx.max_fee
        )
    );

    // Test error type.
    assert!(matches!(
        execution_error,
        TransactionExecutionError::FeeTransferError(FeeTransferError::MaxFeeExceeded { .. })
    ));
}

#[test]
fn test_invoke_tx_with_invalid_version() {
    let (_, mut invoke_tx) = get_tested_valid_invoke_tx();
    let expected_allowed_versions = vec![TransactionVersion(StarkFelt::from(1))];

    // Currently, the only supported version is 1.
    // Note: there is no need to test for a negative version, as it cannot be constructed.
    for invalid_version_id in [0, 2, 12345] {
        let invalid_tx_version = TransactionVersion(StarkHash::from(invalid_version_id));
        invoke_tx.version = invalid_tx_version;
        // TODO(Adi, 20/12/2022): Define a `state` object before the for-loop and use it once
        // `execute` gets a reference to state.
        let execution_error = invoke_tx.execute(CachedState::default()).unwrap_err();

        // Test error message.
        assert_eq!(
            execution_error.to_string(),
            format!(
                "Transaction version {:?} is not supported. Supported versions: {:?}.",
                invalid_tx_version, &expected_allowed_versions
            )
        );

        // Test error type.
        assert!(matches!(
            execution_error,
            TransactionExecutionError::InvalidTransactionVersion { .. }
        ));
    }
}
