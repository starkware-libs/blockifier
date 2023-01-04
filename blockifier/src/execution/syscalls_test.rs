use pretty_assertions::assert_eq;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::Calldata;
use starknet_api::{patricia_key, stark_felt};

use crate::execution::entry_point::{CallEntryPoint, CallExecution, CallInfo, Retdata};
use crate::retdata;
use crate::state::state_api::State;
use crate::test_utils::{
    create_test_state, trivial_external_entry_point, TEST_CALL_CONTRACT_SELECTOR, TEST_CLASS_HASH,
    TEST_CONTRACT_ADDRESS, TEST_DEPLOY_SELECTOR, TEST_LIBRARY_CALL_SELECTOR,
    TEST_NESTED_LIBRARY_CALL_SELECTOR, TEST_STORAGE_READ_WRITE_SELECTOR,
};

#[test]
fn test_storage_read_write() {
    let mut state = create_test_state();
    let key = stark_felt!(1234);
    let value = stark_felt!(18);
    let calldata = Calldata(vec![key, value].into());
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(stark_felt!(TEST_STORAGE_READ_WRITE_SELECTOR)),
        ..trivial_external_entry_point()
    };
    let storage_address = entry_point_call.storage_address;
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![stark_felt!(value)] }
    );
    // Verify that the state has changed.
    let value_from_state = *state.get_storage_at(storage_address, key.try_into().unwrap()).unwrap();
    assert_eq!(value_from_state, value);
}

#[test]
fn test_library_call() {
    let mut state = create_test_state();
    let calldata = Calldata(
        vec![
            stark_felt!(TEST_CLASS_HASH),                  // Class hash.
            stark_felt!(TEST_STORAGE_READ_WRITE_SELECTOR), // Function selector.
            stark_felt!(2),                                // Calldata length.
            stark_felt!(1234),                             // Calldata: address.
            stark_felt!(91),                               // Calldata: value.
        ]
        .into(),
    );
    let entry_point_call = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(TEST_LIBRARY_CALL_SELECTOR)),
        calldata,
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![stark_felt!(91)] }
    );
}

#[test]
fn test_nested_library_call() {
    let mut state = create_test_state();
    let (key, value) = (255, 44);
    let calldata = Calldata(
        vec![
            stark_felt!(TEST_CLASS_HASH),                  // Class hash.
            stark_felt!(TEST_LIBRARY_CALL_SELECTOR),       // Library call function selector.
            stark_felt!(TEST_STORAGE_READ_WRITE_SELECTOR), // Storage function selector.
            stark_felt!(2),                                // Calldata length.
            stark_felt!(key),                              // Calldata: address.
            stark_felt!(value),                            // Calldata: value.
        ]
        .into(),
    );

    // Create expected call info tree.
    let main_entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(TEST_NESTED_LIBRARY_CALL_SELECTOR)),
        calldata,
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        ..trivial_external_entry_point()
    };
    let nested_storage_entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(TEST_STORAGE_READ_WRITE_SELECTOR)),
        calldata: Calldata(vec![stark_felt!(key + 1), stark_felt!(value + 1)].into()),
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        ..trivial_external_entry_point()
    };
    let library_entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(TEST_LIBRARY_CALL_SELECTOR)),
        calldata: Calldata(
            vec![
                stark_felt!(TEST_CLASS_HASH),                  // Class hash.
                stark_felt!(TEST_STORAGE_READ_WRITE_SELECTOR), // Storage function selector.
                stark_felt!(2),                                // Calldata length.
                stark_felt!(key + 1),                          // Calldata: address.
                stark_felt!(value + 1),                        // Calldata: value.
            ]
            .into(),
        ),
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        ..trivial_external_entry_point()
    };
    let storage_entry_point = CallEntryPoint {
        calldata: Calldata(vec![stark_felt!(key), stark_felt!(value)].into()),
        ..nested_storage_entry_point.clone()
    };
    let nested_storage_call_info = CallInfo {
        call: nested_storage_entry_point,
        execution: CallExecution { retdata: retdata![stark_felt!(value + 1)] },
        ..Default::default()
    };
    let library_call_info = CallInfo {
        call: library_entry_point,
        execution: CallExecution { retdata: retdata![stark_felt!(value + 1)] },
        inner_calls: vec![nested_storage_call_info],
        ..Default::default()
    };
    let storage_call_info = CallInfo {
        call: storage_entry_point,
        execution: CallExecution { retdata: retdata![stark_felt!(value)] },
        ..Default::default()
    };
    let expected_call_info = CallInfo {
        call: main_entry_point.clone(),
        execution: CallExecution { retdata: retdata![stark_felt!(0)] },
        inner_calls: vec![library_call_info, storage_call_info],
        ..Default::default()
    };

    assert_eq!(main_entry_point.execute_directly(&mut state).unwrap(), expected_call_info);
}

#[test]
fn test_call_contract() {
    let mut state = create_test_state();
    let calldata = Calldata(
        vec![
            stark_felt!(TEST_CONTRACT_ADDRESS),            // Contract address.
            stark_felt!(TEST_STORAGE_READ_WRITE_SELECTOR), // Function selector.
            stark_felt!(2),                                // Calldata length.
            stark_felt!(405),                              // Calldata: address.
            stark_felt!(48),                               // Calldata: value.
        ]
        .into(),
    );
    let entry_point_call = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(TEST_CALL_CONTRACT_SELECTOR)),
        calldata,
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![stark_felt!(48)] }
    );
}

// TODO(Noa, 30/12/22): Add a test with no constructor
#[test]
fn test_deploy_with_constructor() {
    let mut state = create_test_state();
    let calldata = Calldata(
        vec![
            stark_felt!(TEST_CLASS_HASH), // Class hash.
            stark_felt!(1),               // Contract_address_salt.
            stark_felt!(2),               // Calldata length.
            stark_felt!(1),               // Calldata: address.
            stark_felt!(1),               // Calldata: value.
        ]
        .into(),
    );
    let entry_point_call = CallEntryPoint {
        entry_point_selector: EntryPointSelector(stark_felt!(TEST_DEPLOY_SELECTOR)),
        calldata,
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { retdata: retdata![stark_felt!(1)] }
    );
    let contract_address_from_state =
        *state.get_class_hash_at(ContractAddress(patricia_key!(1))).unwrap();
    assert_eq!(contract_address_from_state, ClassHash(stark_felt!(TEST_CLASS_HASH)));
}
