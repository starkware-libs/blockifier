use std::collections::HashMap;

use assert_matches::assert_matches;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector, Nonce};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{
    Calldata, Fee, InvokeTransaction, TransactionHash, TransactionSignature, TransactionVersion,
};
use starknet_api::{shash, StarknetApiError};

use crate::execution::entry_point::{CallEntryPoint, CallExecution, CallInfo, Retdata};
use crate::retdata;
use crate::state::cached_state::{CachedState, DictStateReader};
use crate::test_utils::{
    get_contract_class, ACCOUNT_CONTRACT_PATH, RETURN_RESULT_SELECTOR,
    TEST_ACCOUNT_CONTRACT_ADDRESS, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CONTRACT_ADDRESS,
};
use crate::transaction::constants::{
    CALL_CONTRACT_CALLDATA_INDEX, EXECUTE_ENTRY_POINT_SELECTOR, VALIDATE_ENTRY_POINT_SELECTOR,
};
use crate::transaction::errors::{FeeTransferError, TransactionExecutionError};
use crate::transaction::objects::{
    ResourcesMapping, TransactionExecutionInfo, TransactionExecutionResult,
};
use crate::transaction::ExecuteTransaction;

// TODO(Adi, 25/12/2022): Use (or create) a `create_test_state` test utils function.
fn create_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = HashMap::from([(
        ClassHash(shash!(TEST_ACCOUNT_CONTRACT_CLASS_HASH)),
        get_contract_class(ACCOUNT_CONTRACT_PATH),
    )]);
    CachedState::new(DictStateReader { class_hash_to_class, ..Default::default() })
}

fn get_tested_valid_invoke_tx() -> Result<InvokeTransaction, StarknetApiError> {
    let execute_calldata = Calldata(
        vec![
            StarkFelt::try_from(TEST_CONTRACT_ADDRESS)?, // Contract address.
            StarkFelt::try_from(RETURN_RESULT_SELECTOR)?, // EP selector.
            StarkFelt::from(1),                          // Calldata length.
            StarkFelt::from(0),                          // Calldata.
        ]
        .into(),
    );

    let invoke_tx = InvokeTransaction {
        transaction_hash: TransactionHash(StarkHash::default()),
        max_fee: Fee(1),
        version: TransactionVersion(StarkFelt::from(1)),
        signature: TransactionSignature(vec![StarkHash::default()]),
        nonce: Nonce::default(),
        // TODO(Adi, 25/12/2022): Use an actual contract_address once there is a mapping from a
        // contract address to its class hash.
        sender_address: ContractAddress::try_from(shash!(TEST_ACCOUNT_CONTRACT_ADDRESS)).unwrap(),
        entry_point_selector: None,
        calldata: execute_calldata,
    };

    Ok(invoke_tx)
}

fn get_tested_actual_fee() -> Fee {
    Fee(1)
}

#[test]
fn test_invoke_tx() -> TransactionExecutionResult<()> {
    let mut state = create_test_state();
    let tx = get_tested_valid_invoke_tx()?;

    // Create expected result object.
    let expected_validate_call_info = CallInfo {
        call: CallEntryPoint {
            class_hash: ClassHash(shash!(TEST_ACCOUNT_CONTRACT_CLASS_HASH)),
            entry_point_type: EntryPointType::External,
            entry_point_selector: EntryPointSelector(shash!(VALIDATE_ENTRY_POINT_SELECTOR)),
            calldata: tx.calldata.clone(),
            storage_address: ContractAddress::try_from(shash!(TEST_ACCOUNT_CONTRACT_ADDRESS))?,
            caller_address: ContractAddress::default(),
        },
        // 'account_without_some_syscalls' has a trivial `validate` function.
        execution: CallExecution { retdata: retdata![] },
        ..Default::default()
    };

    let expected_execute_call = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(EXECUTE_ENTRY_POINT_SELECTOR)),
        ..expected_validate_call_info.call.clone()
    };

    let expected_execute_call_info = CallInfo {
        call: expected_execute_call,
        // The called EP simply returns the calldata it was given.
        execution: CallExecution {
            retdata: Retdata(tx.calldata.0[CALL_CONTRACT_CALLDATA_INDEX..].to_vec().into()),
        },
        ..Default::default()
    };

    let expected_execution_info = TransactionExecutionInfo {
        validate_call_info: expected_validate_call_info,
        execute_call_info: Some(expected_execute_call_info),
        fee_transfer_call_info: CallInfo::default(),
        actual_fee: get_tested_actual_fee(),
        actual_resources: ResourcesMapping::default(),
    };

    let actual_execution_info = tx.execute(&mut state)?;
    assert_eq!(actual_execution_info, expected_execution_info);

    Ok(())
}

#[test]
fn test_negative_invoke_tx_flows() -> TransactionExecutionResult<()> {
    let mut state = create_test_state();
    let valid_tx = get_tested_valid_invoke_tx()?;

    // Invalid version.
    // Note: there is no need to test for a negative version, as it cannot be constructed.
    let invalid_tx_version = TransactionVersion(StarkHash::from(0));
    let invalid_tx = InvokeTransaction { version: invalid_tx_version, ..valid_tx.clone() };
    let execution_error = invalid_tx.execute(&mut state).unwrap_err();

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

    // Insufficient fee.
    let tx_max_fee = Fee(0);
    let invalid_tx = InvokeTransaction { max_fee: tx_max_fee, ..valid_tx };
    let execution_error = invalid_tx.execute(&mut state).unwrap_err();

    // Test error.
    let expected_actual_fee = get_tested_actual_fee();
    assert_matches!(
        execution_error,
        TransactionExecutionError::FeeTransferError(FeeTransferError::MaxFeeExceeded {
            max_fee,
            actual_fee,
        })
        if (max_fee, actual_fee) == (tx_max_fee, expected_actual_fee)
    );

    Ok(())
}
