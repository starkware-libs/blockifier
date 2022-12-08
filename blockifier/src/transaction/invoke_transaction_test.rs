use std::collections::HashMap;
use std::rc::Rc;

use assert_matches::assert_matches;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{
    CallData, Fee, InvokeTransaction, TransactionHash, TransactionSignature, TransactionVersion,
};
use starknet_api::{shash, StarknetApiError};

use crate::cached_state::{CachedState, DictStateReader};
use crate::execution::entry_point::{CallExecution, CallInfo};
use crate::test_utils::{get_contract_class, RETURN_RESULT_SELECTOR, TEST_CONTRACT_ADDRESS};
use crate::transaction::constants::{
    ACCOUNT_CONTRACT_ADDRESS, ACCOUNT_CONTRACT_CLASS_HASH, ACCOUNT_CONTRACT_PATH,
    CALL_CONTRACT_CALLDATA_INDEX,
};
use crate::transaction::errors::{FeeTransferError, TransactionExecutionError};
use crate::transaction::objects::{
    ResourcesMapping, TransactionExecutionInfo, TransactionExecutionResult,
};
use crate::transaction::ExecuteTransaction;

// TODO(Adi, 25/12/2022): Use (or create) a `create_test_state` test utils function.
fn create_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = HashMap::from([(
        ClassHash(shash!(ACCOUNT_CONTRACT_CLASS_HASH)),
        Rc::new(get_contract_class(ACCOUNT_CONTRACT_PATH)),
    )]);
    CachedState::new(DictStateReader { class_hash_to_class, ..Default::default() })
}

fn get_tested_valid_invoke_tx() -> Result<InvokeTransaction, StarknetApiError> {
    // The calldata given to the called contract entrypoint selector.
    let call_contract_calldata = vec![StarkFelt::from(0)];
    let mut execute_calldata = vec![
        StarkFelt::try_from(TEST_CONTRACT_ADDRESS)?,          // Called contract address.
        StarkFelt::try_from(RETURN_RESULT_SELECTOR)?,         // Called contract selector.
        StarkFelt::from(call_contract_calldata.len() as u64), // Called contract calldata length.
    ];
    // Add the `call_contract_calldata` as the called contract calldata.
    execute_calldata.extend_from_slice(&call_contract_calldata);

    let invoke_tx = InvokeTransaction {
        transaction_hash: TransactionHash(StarkHash::default()),
        max_fee: Fee(1),
        version: TransactionVersion(StarkFelt::from(1)),
        signature: TransactionSignature(vec![StarkHash::default()]),
        nonce: Nonce::default(),
        // TODO(Adi, 25/12/2022): Use an actual contract_address once there is a mapping from a
        // contract address to its class hash.
        contract_address: ContractAddress::try_from(shash!(ACCOUNT_CONTRACT_ADDRESS)).unwrap(),
        entry_point_selector: None,
        calldata: CallData(execute_calldata),
    };

    Ok(invoke_tx)
}

fn get_tested_actual_fee() -> Fee {
    Fee(1)
}

#[test]
fn test_invoke_tx() -> TransactionExecutionResult<()> {
    let state = create_test_state();
    let tx = get_tested_valid_invoke_tx()?;

    let execute_result = tx.execute(state)?;

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

    let tx_calldata = tx.calldata.0;
    assert_matches!(
        &execute_result.execute_info,
        Some(CallInfo { call: _, execution, inner_calls })
        // 'account_without_some_syscalls' simply returns the calldata it was given.
        if (execution, inner_calls) == (
            &CallExecution{retdata: tx_calldata[CALL_CONTRACT_CALLDATA_INDEX..].to_vec()}, &vec![]
        )
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
fn test_invalid_invoke_tx() -> TransactionExecutionResult<()> {
    let state = create_test_state();
    let valid_tx = get_tested_valid_invoke_tx()?;

    // Invalid version case.
    // Note: there is no need to test for a negative version, as it cannot be constructed.
    let invalid_tx_version = TransactionVersion(StarkHash::from(0));
    let invalid_tx = InvokeTransaction { version: invalid_tx_version, ..valid_tx.clone() };
    let execution_error = invalid_tx.execute(state.clone()).unwrap_err();

    // Test error.
    let expected_allowed_versions = vec![TransactionVersion(StarkFelt::from(1))];
    assert_matches!(
        execution_error,
        TransactionExecutionError::InvalidTransactionVersion {
            tx_version,
            allowed_versions,
        }
        if (tx_version, &allowed_versions) == (invalid_tx_version, &expected_allowed_versions)
    );

    // Insufficient fee case.
    let invalid_tx = InvokeTransaction { max_fee: Fee(0), ..valid_tx };
    let execution_error = invalid_tx.execute(state).unwrap_err();

    // Test error.
    let expected_actual_fee = get_tested_actual_fee();
    assert_matches!(
        execution_error,
        TransactionExecutionError::FeeTransferError(FeeTransferError::MaxFeeExceeded {
            max_fee,
            actual_fee,
        })
        if (max_fee, actual_fee) == (invalid_tx.max_fee, expected_actual_fee)
    );

    Ok(())
}
