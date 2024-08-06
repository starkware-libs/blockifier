use pretty_assertions::assert_eq;
use starknet_api::core::calculate_contract_address;
use starknet_api::transaction::{Calldata, ContractAddressSalt};
use starknet_api::{calldata, felt};
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::context::ChainInfo;
use crate::execution::call_info::{CallExecution, Retdata};
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::native::utils::NATIVE_GAS_PLACEHOLDER;
use crate::execution::syscalls::syscall_tests::utils::assert_consistent_contract_version;
use crate::retdata;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{calldata_for_deploy_test, trivial_external_entry_point_new, CairoVersion};

// TODO add all combinations of Native and Vm deployer and deployee
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1);"VM")]
#[test_case(FeatureContract::SierraTestContract;"Native")]
fn no_constructor(deployer_contract: FeatureContract) {
    let empty_contract = FeatureContract::Empty(CairoVersion::Cairo1);
    let class_hash = empty_contract.get_class_hash();

    let mut state = test_state(
        &ChainInfo::create_for_testing(),
        0,
        &[(deployer_contract, 1), (empty_contract, 0)],
    );

    assert_consistent_contract_version(deployer_contract, &state);
    assert_consistent_contract_version(empty_contract, &state);

    let calldata = calldata_for_deploy_test(class_hash, &[], true);
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_deploy"),
        calldata,
        ..trivial_external_entry_point_new(deployer_contract)
    };
    let deployed_contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &calldata![],
        deployer_contract.get_instance_address(0),
    )
    .unwrap();

    let deploy_call = &entry_point_call.execute_directly(&mut state).unwrap().inner_calls[0];

    assert_eq!(deploy_call.call.storage_address, deployed_contract_address);
    assert_eq!(
        deploy_call.execution,
        CallExecution { retdata: retdata![], gas_consumed: 0, ..CallExecution::default() }
    );
    assert_eq!(state.get_class_hash_at(deployed_contract_address).unwrap(), class_hash);

    assert_consistent_contract_version(deployer_contract, &state);
    assert_consistent_contract_version(empty_contract, &state);
}

#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1);"VM")]
#[test_case(FeatureContract::SierraTestContract;"Native")]
fn no_constructor_nonempty_calldata(deployer_contract: FeatureContract) {
    let empty_contract = FeatureContract::Empty(CairoVersion::Cairo1);
    let class_hash = empty_contract.get_class_hash();

    let mut state = test_state(
        &ChainInfo::create_for_testing(),
        0,
        &[(deployer_contract, 1), (empty_contract, 0)],
    );
    assert_consistent_contract_version(deployer_contract, &state);
    assert_consistent_contract_version(empty_contract, &state);

    let calldata = calldata_for_deploy_test(class_hash, &[felt!(1_u8), felt!(1_u8)], true);

    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_deploy"),
        calldata,
        ..trivial_external_entry_point_new(deployer_contract)
    };

    let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert!(error.contains(
        "Invalid input: constructor_calldata; Cannot pass calldata to a contract with no \
         constructor."
    ));

    assert_consistent_contract_version(deployer_contract, &state);
    assert_consistent_contract_version(empty_contract, &state);
}

#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), 10140;"VM")]
#[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER;"Native")]
fn with_constructor(deployer_contract: FeatureContract, expected_gas: u64) {
    let empty_contract = FeatureContract::Empty(CairoVersion::Cairo1);
    let mut state = test_state(
        &ChainInfo::create_for_testing(),
        0,
        &[(deployer_contract, 1), (empty_contract, 0)],
    );
    assert_consistent_contract_version(deployer_contract, &state);
    assert_consistent_contract_version(empty_contract, &state);

    let class_hash = deployer_contract.get_class_hash();
    let constructor_calldata = vec![
        felt!(1_u8), // Calldata: address.
        felt!(1_u8), // Calldata: value.
    ];

    let calldata = calldata_for_deploy_test(class_hash, &constructor_calldata, true);

    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_deploy"),
        calldata,
        ..trivial_external_entry_point_new(deployer_contract)
    };

    // No errors expected.
    let contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &Calldata(constructor_calldata.clone().into()),
        deployer_contract.get_instance_address(0),
    )
    .unwrap();
    let deploy_call = &entry_point_call.execute_directly(&mut state).unwrap().inner_calls[0];

    assert_eq!(deploy_call.call.storage_address, contract_address);
    assert_eq!(
        deploy_call.execution,
        CallExecution {
            retdata: retdata![constructor_calldata[0]],
            gas_consumed: expected_gas,
            ..CallExecution::default()
        }
    );
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), class_hash);

    assert_consistent_contract_version(deployer_contract, &state);
    assert_consistent_contract_version(empty_contract, &state);
}

#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1);"VM")]
#[test_case(FeatureContract::SierraTestContract;"Native")]
fn to_unavailable_address(deployer_contract: FeatureContract) {
    let empty_contract = FeatureContract::Empty(CairoVersion::Cairo1);
    let mut state = test_state(
        &ChainInfo::create_for_testing(),
        0,
        &[(deployer_contract, 1), (empty_contract, 0)],
    );
    assert_consistent_contract_version(deployer_contract, &state);
    assert_consistent_contract_version(empty_contract, &state);

    let class_hash = deployer_contract.get_class_hash();
    let constructor_calldata = vec![
        felt!(1_u8), // Calldata: address.
        felt!(1_u8), // Calldata: value.
    ];

    let calldata = calldata_for_deploy_test(class_hash, &constructor_calldata, true);

    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_deploy"),
        calldata,
        ..trivial_external_entry_point_new(deployer_contract)
    };

    entry_point_call.clone().execute_directly(&mut state).unwrap();
    let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();

    assert!(error.contains("is unavailable for deployment."));

    assert_consistent_contract_version(deployer_contract, &state);
    assert_consistent_contract_version(empty_contract, &state);
}
