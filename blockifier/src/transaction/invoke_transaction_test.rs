use std::collections::HashMap;
use std::rc::Rc;

use assert_matches::assert_matches;
use pretty_assertions::assert_eq;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{
    CallData, Fee, InvokeTransaction, TransactionHash, TransactionSignature, TransactionVersion,
};
use starknet_api::{shash, StarknetApiError};

use crate::cached_state::{CachedState, DictStateReader};
use crate::execution::entry_point::test::{RETURN_RESULT_SELECTOR, TEST_CONTRACT_ADDRESS};
use crate::execution::entry_point::{CallExecution, CallInfo};
use crate::transaction::constants::{ACCOUNT_CONTRACT_CLASS_HASH, ACCOUNT_CONTRACT_PATH};
use crate::transaction::errors::{FeeTransferError, TransactionExecutionError};
use crate::transaction::objects::{
    ResourcesMapping, TransactionExecutionInfo, TransactionExecutionResult,
};
use crate::transaction::transaction_utils::get_contract_class;
use crate::transaction::ExecuteTransaction;

// TODO(Adi, 25/12/2022): Use (or create) a `create_test_state` test utils function.
fn create_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = HashMap::from([(
        ClassHash(shash!(ACCOUNT_CONTRACT_CLASS_HASH)),
        Rc::new(get_contract_class(ACCOUNT_CONTRACT_PATH)),
    )]);
    CachedState::new(DictStateReader { class_hash_to_class, ..Default::default() })
}

fn get_tested_valid_invoke_tx() -> Result<(Vec<StarkHash>, InvokeTransaction), StarknetApiError> {
    // The calldata given to the contract address selector, specified in the invoke transaction
    // calldata.
    let call_contract_calldata = vec![StarkFelt::from(0)];
    let mut execute_calldata = vec![
        // contract_address.
        StarkFelt::try_from(TEST_CONTRACT_ADDRESS)?,
        // selector.
        StarkFelt::try_from(RETURN_RESULT_SELECTOR)?,
        // calldata_len.
        StarkFelt::from(call_contract_calldata.len() as u64),
    ];
    // Add the `call_contract_calldata` as calldata.
    execute_calldata.extend_from_slice(&call_contract_calldata);

    let invoke_tx = InvokeTransaction {
        transaction_hash: TransactionHash(StarkHash::default()),
        max_fee: Fee(1),
        version: TransactionVersion(StarkFelt::from(1)),
        signature: TransactionSignature(vec![StarkHash::default()]),
        nonce: Nonce::default(),
        // TODO(Adi, 25/12/2022): Use an actual contract_address once there is a mapping from a
        // contract address to its class hash.
        contract_address: ContractAddress::try_from(shash!("0x1")).unwrap(),
        entry_point_selector: None,
        calldata: CallData(execute_calldata),
    };

    Ok((call_contract_calldata, invoke_tx))
}

fn get_tested_actual_fee() -> Fee {
    Fee(1)
}

#[test]
fn test_invoke_tx() -> TransactionExecutionResult<()> {
    let state = create_test_state();
    let (call_contract_calldata, invoke_tx) = get_tested_valid_invoke_tx()?;

    let execute_result = invoke_tx.execute(state)?;

    // TODO(Adi, 20/12/2022): Replace the following `matches!` assertions with a single `assert_eq`
    // assertion and test the whole CallInfo object.
    assert_matches!(
        &execute_result,
        TransactionExecutionInfo {
            execute_info:_, actual_fee, validate_info: _, fee_transfer_info, actual_resources
        }
        if (actual_fee, fee_transfer_info, actual_resources) == (
            &get_tested_actual_fee(), &CallInfo::default(), &ResourcesMapping::default())
    );

    assert_matches!(
        &execute_result.execute_info,
        Some(CallInfo { call: _, execution, inner_calls })
        // 'account_without_some_syscalls' simply returns the calldata it was given.
        if (execution, inner_calls) == (&CallExecution{retdata: call_contract_calldata}, &vec![])
    );

    assert_matches!(
        &execute_result.validate_info,
        CallInfo { call: _, execution, inner_calls }
        // 'account_without_some_syscalls' has a trivial `validate` function.
        if (execution, inner_calls) == (&CallExecution{retdata: vec![]}, &vec![])
    );

    Ok(())
}

#[test]
fn test_invoke_tx_with_insufficient_fee() -> TransactionExecutionResult<()> {
    let state = create_test_state();
    let (_, mut invoke_tx) = get_tested_valid_invoke_tx()?;
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
    assert_matches!(
        execution_error,
        TransactionExecutionError::FeeTransferError(FeeTransferError::MaxFeeExceeded { .. })
    );

    Ok(())
}

#[test]
fn test_invoke_tx_with_invalid_version() -> TransactionExecutionResult<()> {
    let state = create_test_state();
    let (_, mut invoke_tx) = get_tested_valid_invoke_tx()?;
    let expected_allowed_versions = vec![TransactionVersion(StarkFelt::from(1))];

    // TODO(Adi, 25/12/2022): Use `test_case` feature and define the several invalid version cases.
    // Currently, the only supported version is 1.
    // Note: there is no need to test for a negative version, as it cannot be constructed.
    for invalid_version_id in [0, 2, 12345] {
        let invalid_tx_version = TransactionVersion(StarkHash::from(invalid_version_id));
        invoke_tx.version = invalid_tx_version;
        let execution_error = invoke_tx.execute(state.clone()).unwrap_err();

        // Test error message.
        assert_eq!(
            execution_error.to_string(),
            format!(
                "Transaction version {:?} is not supported. Supported versions: {:?}.",
                invalid_tx_version, &expected_allowed_versions
            )
        );

        // Test error type.
        assert_matches!(
            execution_error,
            TransactionExecutionError::InvalidTransactionVersion { .. }
        );
    }

    Ok(())
}
