use pretty_assertions::assert_eq;
use starknet_api::core::ContractAddress;
use starknet_api::state::StorageKey;
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, felt};
use starknet_types_core::felt::Felt;
use test_case::test_case;

use super::utils::assert_consistent_contract_version;
use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants;
use crate::context::ChainInfo;
use crate::execution::call_info::{CallExecution, Retdata};
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::native::utils::NATIVE_GAS_PLACEHOLDER;
use crate::state::cached_state::CachedState;
use crate::state::state_api::State;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{
    trivial_external_entry_point_new, CairoVersion, BALANCE, CURRENT_BLOCK_NUMBER,
};
use crate::{check_entry_point_execution_error_for_custom_hint, retdata};

fn initialize_state(test_contract: FeatureContract) -> (CachedState<DictStateReader>, Felt, Felt) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);
    assert_consistent_contract_version(test_contract, &state);

    // Initialize block number -> block hash entry.
    let upper_bound_block_number = CURRENT_BLOCK_NUMBER - constants::STORED_BLOCK_HASH_BUFFER;
    let block_number = felt!(upper_bound_block_number);
    let block_hash = felt!(66_u64);
    let key = StorageKey::try_from(block_number).unwrap();
    let block_hash_contract_address =
        ContractAddress::try_from(Felt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS)).unwrap();
    state.set_storage_at(block_hash_contract_address, key, block_hash).unwrap();

    (state, block_number, block_hash)
}

#[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), 9680; "VM")]
fn positive_flow(test_contract: FeatureContract, expected_gas: u64) {
    let (mut state, block_number, block_hash) = initialize_state(test_contract);

    let calldata = calldata![block_number];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_get_block_hash"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    assert_eq!(
        entry_point_call.clone().execute_directly(&mut state).unwrap().execution,
        CallExecution {
            gas_consumed: expected_gas,
            ..CallExecution::from_retdata(retdata![block_hash])
        }
    );

    assert_consistent_contract_version(test_contract, &state);
}

#[test_case(FeatureContract::SierraTestContract; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")]
fn negative_flow_execution_mode_validate(test_contract: FeatureContract) {
    let (mut state, block_number, _) = initialize_state(test_contract);

    let calldata = calldata![block_number];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_get_block_hash"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    let error = entry_point_call.execute_directly_in_validate_mode(&mut state).unwrap_err();

    // While executing with native it fails with `Unexpected structure for error:
    // NativeExecutionError { info: "Unauthorized syscall get_block_hash in execution mode
    // Validate." }`
    if matches!(test_contract, FeatureContract::TestContract(_)) {
        check_entry_point_execution_error_for_custom_hint!(
            &error,
            "Unauthorized syscall get_block_hash in execution mode Validate.",
        );
    }

    assert!(
        error
            .to_string()
            .contains("Unauthorized syscall get_block_hash in execution mode Validate")
    );

    assert_consistent_contract_version(test_contract, &state);
}

#[test_case(FeatureContract::SierraTestContract; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")]
fn negative_flow_block_number_out_of_range(test_contract: FeatureContract) {
    let (mut state, _, _) = initialize_state(test_contract);

    let requested_block_number = CURRENT_BLOCK_NUMBER - constants::STORED_BLOCK_HASH_BUFFER + 1;
    let block_number = felt!(requested_block_number);
    let calldata = calldata![block_number];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_get_block_hash"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
    assert!(error.contains("Block number out of range"));
    assert_consistent_contract_version(test_contract, &state);
}
