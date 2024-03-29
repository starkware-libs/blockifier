use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{Calldata, ContractAddressSalt};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::execution::call_info::{CallExecution, Retdata};
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::native::utils::NATIVE_GAS_PLACEHOLDER;
use crate::retdata;
use crate::state::state_api::StateReader;
use crate::test_utils::cached_state::create_deploy_test_state;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::{
    trivial_external_entry_point, CairoVersion, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS,
    TEST_EMPTY_CONTRACT_CLASS_HASH,
};

#[test_case(
    FeatureContract::SierraTestContract;
    "Native"
)]
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1);
    "VM"
)]
fn no_constructor(feature_contract: FeatureContract) {
    let mut state = create_deploy_test_state(feature_contract);
    let class_hash = class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH);
    let calldata = calldata![
        stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH),
        ContractAddressSalt::default().0,
        stark_felt!(0_u8),
        stark_felt!(0_u8)
    ];

    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_deploy"),
        calldata,
        ..trivial_external_entry_point()
    };

    // No errors expected.
    let contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &calldata![],
        contract_address!(TEST_CONTRACT_ADDRESS),
    )
    .unwrap();

    let deploy_call = &entry_point_call.execute_directly(&mut state).unwrap().inner_calls[0];

    pretty_assertions::assert_eq!(deploy_call.call.storage_address, contract_address);
    pretty_assertions::assert_eq!(
        deploy_call.execution,
        CallExecution { retdata: retdata![], gas_consumed: 0, ..CallExecution::default() }
    );
    pretty_assertions::assert_eq!(state.get_class_hash_at(contract_address).unwrap(), class_hash);
}

#[test_case(
    FeatureContract::SierraTestContract;
    "Native"
)]
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1);
    "VM"
)]
fn no_constructor_nonempty_calldata(feature_contract: FeatureContract) {
    let calldata = calldata![
        stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH),
        ContractAddressSalt::default().0,
        stark_felt!(2_u8),
        stark_felt!(2_u8),
        stark_felt!(1_u8),
        stark_felt!(0_u8)
    ];

    let mut state = create_deploy_test_state(feature_contract);
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_deploy"),
        calldata,
        ..trivial_external_entry_point()
    };

    let execution_result = entry_point_call.execute_directly(&mut state);
    let error = execution_result.unwrap_err().to_string();

    assert!(error.contains("Cannot pass calldata to a contract with no constructor"));
}

#[test_case(
    FeatureContract::SierraTestContract,
    NATIVE_GAS_PLACEHOLDER;
    "Native"
)]
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    16640;
    "VM"
)]
fn with_constructor(feature_contract: FeatureContract, gas: u64) {
    let class_hash = class_hash!(TEST_CLASS_HASH);
    let calldata = calldata![
        stark_felt!(TEST_CLASS_HASH),     // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2_u8),                // Calldata length.
        stark_felt!(1_u8),                // Calldata: arg1.
        stark_felt!(1_u8),                // Calldata: arg2.
        stark_felt!(0_u8)                 // deploy_from_zero.
    ];
    let constructor_calldata = calldata![
        stark_felt!(1_u8), // Calldata: arg1.
        stark_felt!(1_u8)  // Calldata: arg2.
    ];

    let mut state = create_deploy_test_state(feature_contract);
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_deploy"),
        calldata,
        ..trivial_external_entry_point()
    };

    // No errors expected.
    let contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &constructor_calldata,
        contract_address!(TEST_CONTRACT_ADDRESS),
    )
    .unwrap();

    let deploy_call = &entry_point_call.execute_directly(&mut state).unwrap().inner_calls[0];

    pretty_assertions::assert_eq!(deploy_call.call.storage_address, contract_address);
    pretty_assertions::assert_eq!(
        deploy_call.execution,
        CallExecution {
            retdata: retdata![constructor_calldata.0[0]],
            gas_consumed: gas,
            ..CallExecution::default()
        }
    );
    pretty_assertions::assert_eq!(state.get_class_hash_at(contract_address).unwrap(), class_hash);
}

#[test_case(
    FeatureContract::SierraTestContract;
    "Native"
)]
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1);
    "VM"
)]
fn with_constructor_deploy_to_the_same_address(feature_contract: FeatureContract) {
    let calldata = calldata![
        stark_felt!(TEST_CLASS_HASH),     // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2_u8),                // Calldata length.
        stark_felt!(3_u8),                // Calldata: arg1.
        stark_felt!(3_u8),                // Calldata: arg2.
        stark_felt!(0_u8)                 // deploy_from_zero.
    ];
    let mut state = create_deploy_test_state(feature_contract);
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_deploy"),
        calldata,
        ..trivial_external_entry_point()
    };

    let execution_result = entry_point_call.execute_directly(&mut state);
    let error = execution_result.unwrap_err().to_string();

    assert!(error.contains("unavailable for deployment"));
}
