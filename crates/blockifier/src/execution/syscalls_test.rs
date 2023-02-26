use std::collections::HashMap;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use pretty_assertions::assert_eq;
use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Calldata, ContractAddressSalt};
use starknet_api::{calldata, patricia_key, stark_felt};
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::execution::entry_point::{CallEntryPoint, CallExecution, CallInfo, Retdata};
use crate::retdata;
use crate::state::cached_state::CachedState;
use crate::state::state_api::State;
use crate::test_utils::{
    create_deploy_test_state, create_test_state, trivial_external_entry_point, DictStateReader,
    TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS, TEST_EMPTY_CONTRACT_CLASS_HASH,
};

#[test]
fn test_storage_read_write() {
    let mut state = create_test_state();
    let key = stark_felt!(1234);
    let value = stark_felt!(18);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        ..trivial_external_entry_point()
    };
    let storage_address = entry_point_call.storage_address;
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![stark_felt!(value)])
    );
    // Verify that the state has changed.
    let value_from_state =
        *state.get_storage_at(storage_address, StorageKey::try_from(key).unwrap()).unwrap();
    assert_eq!(value_from_state, value);
}

#[test]
fn test_library_call() {
    let mut state = create_test_state();
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let calldata = calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        inner_entry_point_selector.0, // Function selector.
        stark_felt!(2),               // Calldata length.
        stark_felt!(1234),            // Calldata: address.
        stark_felt!(91)               // Calldata: value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_library_call"),
        calldata,
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![stark_felt!(91)])
    );
}

#[test]
fn test_nested_library_call() {
    let mut state = create_test_state();
    let (key, value) = (255, 44);
    let outer_entry_point_selector = selector_from_name("test_library_call");
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let calldata = calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        outer_entry_point_selector.0, // Library call function selector.
        inner_entry_point_selector.0, // Storage function selector.
        stark_felt!(2),               // Calldata length.
        stark_felt!(key),             // Calldata: address.
        stark_felt!(value)            // Calldata: value.
    ];

    // Create expected call info tree.
    let main_entry_point = CallEntryPoint {
        entry_point_selector: selector_from_name("test_nested_library_call"),
        calldata,
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        ..trivial_external_entry_point()
    };
    let nested_storage_entry_point = CallEntryPoint {
        entry_point_selector: inner_entry_point_selector,
        calldata: calldata![stark_felt!(key + 1), stark_felt!(value + 1)],
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        ..trivial_external_entry_point()
    };
    let library_entry_point = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata: calldata![
            stark_felt!(TEST_CLASS_HASH), // Class hash.
            inner_entry_point_selector.0, // Storage function selector.
            stark_felt!(2),               // Calldata length.
            stark_felt!(key + 1),         // Calldata: address.
            stark_felt!(value + 1)        // Calldata: value.
        ],
        class_hash: Some(ClassHash(stark_felt!(TEST_CLASS_HASH))),
        ..trivial_external_entry_point()
    };
    let storage_entry_point = CallEntryPoint {
        calldata: calldata![stark_felt!(key), stark_felt!(value)],
        ..nested_storage_entry_point.clone()
    };
    let nested_storage_call_info = CallInfo {
        call: nested_storage_entry_point,
        execution: CallExecution::from_retdata(retdata![stark_felt!(value + 1)]),
        vm_resources: ExecutionResources {
            n_steps: 0,
            n_memory_holes: 1,
            builtin_instance_counter: HashMap::from([
                (String::from("range_check"), 0),
                (String::from("bitwise"), 0),
                (String::from("pedersen"), 0),
            ]),
        },
        ..Default::default()
    };
    let library_call_info = CallInfo {
        call: library_entry_point,
        execution: CallExecution::from_retdata(retdata![stark_felt!(value + 1)]),
        vm_resources: ExecutionResources {
            n_steps: 0,
            n_memory_holes: 1,
            builtin_instance_counter: HashMap::from([
                ("bitwise".to_string(), 0),
                ("range_check".to_string(), 1),
                ("pedersen".to_string(), 0),
            ]),
        },
        inner_calls: vec![nested_storage_call_info],
    };
    let storage_call_info = CallInfo {
        call: storage_entry_point,
        execution: CallExecution::from_retdata(retdata![stark_felt!(value)]),
        vm_resources: ExecutionResources {
            n_steps: 0,
            n_memory_holes: 1,
            builtin_instance_counter: HashMap::from([
                ("bitwise".to_string(), 0),
                ("range_check".to_string(), 0),
                ("pedersen".to_string(), 0),
            ]),
        },
        ..Default::default()
    };
    let expected_call_info = CallInfo {
        call: main_entry_point.clone(),
        execution: CallExecution::from_retdata(retdata![stark_felt!(0)]),
        vm_resources: ExecutionResources {
            n_steps: 0,
            n_memory_holes: 1,
            builtin_instance_counter: HashMap::from([
                ("bitwise".to_string(), 0),
                ("range_check".to_string(), 1),
                ("pedersen".to_string(), 0),
            ]),
        },
        inner_calls: vec![library_call_info, storage_call_info],
    };

    assert_eq!(main_entry_point.execute_directly(&mut state).unwrap(), expected_call_info);
}

#[test]
fn test_call_contract() {
    let mut state = create_test_state();
    let outer_entry_point_selector = selector_from_name("test_call_contract");
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let calldata = calldata![
        stark_felt!(TEST_CONTRACT_ADDRESS), // Contract address.
        inner_entry_point_selector.0,       // Function selector.
        stark_felt!(2),                     // Calldata length.
        stark_felt!(405),                   // Calldata: address.
        stark_felt!(48)                     // Calldata: value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata,
        ..trivial_external_entry_point()
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![stark_felt!(48)])
    );
}

#[test_case(
    ClassHash(stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH)),
    calldata![
    stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
    ContractAddressSalt::default().0, // Contract_address_salt.
    stark_felt!(0), // Calldata length.
    stark_felt!(0) // deploy_from_zero.
    ],
    calldata![],
    None ;
    "No constructor: Positive flow")]
#[test_case(
    ClassHash(stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH)),
    calldata![
        stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2), // Calldata length.
        stark_felt!(2), // Calldata: address.
        stark_felt!(1), // Calldata: value.
        stark_felt!(0) // deploy_from_zero.
    ],
    calldata![
        stark_felt!(2), // Calldata: address.
        stark_felt!(1) // Calldata: value.
    ],
    Some(
    "Invalid input: constructor_calldata; Cannot pass calldata to a contract with no constructor.");
    "No constructor: Negative flow: nonempty calldata")]
#[test_case(
    ClassHash(stark_felt!(TEST_CLASS_HASH)),
    calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2), // Calldata length.
        stark_felt!(1), // Calldata: address.
        stark_felt!(1), // Calldata: value.
        stark_felt!(0) // deploy_from_zero.
    ],
    calldata![
        stark_felt!(1), // Calldata: address.
        stark_felt!(1) // Calldata: value.
    ],
    None;
    "With constructor: Positive flow")]
#[test_case(
    ClassHash(stark_felt!(TEST_CLASS_HASH)),
    calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2), // Calldata length.
        stark_felt!(3), // Calldata: address.
        stark_felt!(3), // Calldata: value.
        stark_felt!(0) // deploy_from_zero.
    ],
    calldata![
        stark_felt!(3), // Calldata: address.
        stark_felt!(3) // Calldata: value.
    ],
    Some("is unavailable for deployment.");
    "With constructor: Negative flow: deploy to the same address")]
#[test_case(
    ClassHash(stark_felt!(TEST_CLASS_HASH)),
    calldata![
        stark_felt!(TEST_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2), // Calldata length.
        stark_felt!(1), // Calldata: address.
        stark_felt!(1), // Calldata: value.
        stark_felt!(2) // deploy_from_zero.
    ],
    calldata![
        stark_felt!(1), // Calldata: address.
        stark_felt!(1) // Calldata: value.
    ],
    Some(&format!(
        "Invalid syscall input: {:?}; {:}",
        stark_felt!(2),
        "The deploy_from_zero field in the deploy system call must be 0 or 1.",
    ));
    "With constructor: Negative flow: illegal value for deploy_from_zero")]
fn test_deploy(
    class_hash: ClassHash,
    calldata: Calldata,
    constructor_calldata: Calldata,
    expected_error: Option<&str>,
) {
    let mut state = create_deploy_test_state();
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_deploy"),
        calldata,
        ..trivial_external_entry_point()
    };

    if let Some(expected_error) = expected_error {
        let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
        assert!(error.contains(expected_error));
        return;
    }

    // No errors expected.
    let contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &constructor_calldata,
        ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS)),
    )
    .unwrap();
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution::from_retdata(retdata![*contract_address.0.key()])
    );
    assert_eq!(*state.get_class_hash_at(contract_address).unwrap(), class_hash);
}

#[test]
fn test_calculate_contract_address() {
    let mut state = create_test_state();

    fn run_test(
        salt: ContractAddressSalt,
        class_hash: ClassHash,
        constructor_calldata: &Calldata,
        calldata: Calldata,
        deployer_address: ContractAddress,
        state: &mut CachedState<DictStateReader>,
    ) {
        let entry_point_call = CallEntryPoint {
            calldata,
            entry_point_selector: selector_from_name("test_contract_address"),
            ..trivial_external_entry_point()
        };
        let contract_address =
            calculate_contract_address(salt, class_hash, constructor_calldata, deployer_address)
                .unwrap();

        assert_eq!(
            entry_point_call.execute_directly(state).unwrap().execution,
            CallExecution::from_retdata(retdata![*contract_address.0.key()])
        );
    }

    let salt = ContractAddressSalt::default();
    let class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    let deployer_address = ContractAddress::try_from(stark_felt!(TEST_CONTRACT_ADDRESS)).unwrap();

    // Without constructor.
    let calldata_no_constructor = calldata![
        salt.0,                    // Contract_address_salt.
        class_hash.0,              // Class hash.
        stark_felt!(0),            // Calldata length.
        *deployer_address.0.key()  // deployer_address.
    ];
    run_test(salt, class_hash, &calldata![], calldata_no_constructor, deployer_address, &mut state);

    // With constructor.
    let constructor_calldata = calldata![stark_felt!(1), stark_felt!(1)];
    let calldata = calldata![
        salt.0,                    // Contract_address_salt.
        class_hash.0,              // Class hash.
        stark_felt!(2),            // Calldata length.
        stark_felt!(1),            // Calldata: address.
        stark_felt!(1),            // Calldata: value.
        *deployer_address.0.key()  // deployer_address.
    ];
    run_test(salt, class_hash, &constructor_calldata, calldata, deployer_address, &mut state);
}
