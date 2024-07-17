use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, stark_felt};
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::context::ChainInfo;
use crate::execution::call_info::CallExecution;
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::native::utils::NATIVE_GAS_PLACEHOLDER;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{trivial_external_entry_point_new, CairoVersion, BALANCE};

#[test_case(FeatureContract::SierraTestContract; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")]
fn undeclared_class_hash(test_contract: FeatureContract) {
    let mut state = test_state(&ChainInfo::create_for_testing(), BALANCE, &[(test_contract, 1)]);

    let entry_point_call = CallEntryPoint {
        calldata: calldata![stark_felt!(1234_u16)],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point_new(test_contract)
    };
    let error = entry_point_call.execute_directly(&mut state, None).unwrap_err().to_string();
    assert!(error.contains("is not declared"));
}

#[test_case(FeatureContract::SierraTestContract; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")]
fn cairo0_class_hash(test_contract: FeatureContract) {
    let empty_contract_cairo0 = FeatureContract::Empty(CairoVersion::Cairo0);
    let mut state = test_state(
        &ChainInfo::create_for_testing(),
        BALANCE,
        &[(test_contract, 1), (empty_contract_cairo0, 0)],
    );

    // Replace with Cairo 0 class hash.
    let v0_class_hash = empty_contract_cairo0.get_class_hash();

    let entry_point_call = CallEntryPoint {
        calldata: calldata![v0_class_hash.0],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point_new(test_contract)
    };
    let error = entry_point_call.execute_directly(&mut state, None).unwrap_err().to_string();
    assert!(error.contains("Cannot replace V1 class hash with V0 class hash"));
}

#[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER; "Native")] // pass
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), 9750; "VM")] // pass
fn positive_flow(test_contract: FeatureContract, gas_consumed: u64) {
    let empty_contract = FeatureContract::Empty(CairoVersion::Cairo1);
    let empty_contract_cairo0 = FeatureContract::Empty(CairoVersion::Cairo0);
    let mut state = test_state(
        &ChainInfo::create_for_testing(),
        BALANCE,
        &[(test_contract, 1), (empty_contract, 0), (empty_contract_cairo0, 0)],
    );
    let contract_address = test_contract.get_instance_address(0);

    let old_class_hash = test_contract.get_class_hash();
    let new_class_hash = empty_contract.get_class_hash();
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), old_class_hash);
    let entry_point_call = CallEntryPoint {
        calldata: calldata![new_class_hash.0],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point_new(test_contract)
    };
    assert_eq!(
        entry_point_call.execute_directly(&mut state, None).unwrap().execution,
        CallExecution { gas_consumed, ..Default::default() }
    );
    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), new_class_hash);
}
