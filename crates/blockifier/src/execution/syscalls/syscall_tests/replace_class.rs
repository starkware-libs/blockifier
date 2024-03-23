use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::execution::call_info::CallExecution;
use crate::execution::contract_class::ContractClassV0;
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::sierra_utils::NATIVE_GAS_PLACEHOLDER;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::cached_state::create_deploy_test_state;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::{
    trivial_external_entry_point, CairoVersion, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS,
    TEST_EMPTY_CONTRACT_CAIRO0_PATH, TEST_EMPTY_CONTRACT_CLASS_HASH,
};

#[test_case(FeatureContract::SierraTestContract; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")]
fn undeclared_class_hash(test_contract: FeatureContract) {
    let mut state = create_deploy_test_state(test_contract);
    let entry_point_call = CallEntryPoint {
        calldata: calldata![stark_felt!(1234_u16)],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point()
    };

    let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert!(error.contains("is not declared"));
}

#[test_case(FeatureContract::SierraTestContract; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")]
fn cairo0_class_hash(test_contract: FeatureContract) {
    let mut state = create_deploy_test_state(test_contract);

    let v0_class_hash = class_hash!(5678_u16);
    let v0_contract_class = ContractClassV0::from_file(TEST_EMPTY_CONTRACT_CAIRO0_PATH).into();
    state.set_contract_class(v0_class_hash, v0_contract_class).unwrap();

    let entry_point_call = CallEntryPoint {
        calldata: calldata![v0_class_hash.0],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point()
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert!(error.contains("Cannot replace V1 class hash with V0 class hash"));
}

#[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER; "Native")] // pass
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), 14450; "VM")] // pass
fn positive_flow(test_contract: FeatureContract, gas_consumed: u64) {
    let mut state = create_deploy_test_state(test_contract);
    let contract_address = contract_address!(TEST_CONTRACT_ADDRESS);
    let current_class_hash = class_hash!(TEST_CLASS_HASH);

    pretty_assertions::assert_eq!(
        state.get_class_hash_at(contract_address).unwrap(),
        current_class_hash
    );

    let new_class_hash = class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH);
    let entry_point_call = CallEntryPoint {
        calldata: calldata![new_class_hash.0],
        entry_point_selector: selector_from_name("test_replace_class"),
        ..trivial_external_entry_point()
    };

    pretty_assertions::assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed, ..Default::default() }
    );
    pretty_assertions::assert_eq!(
        state.get_class_hash_at(contract_address).unwrap(),
        new_class_hash
    );
}
