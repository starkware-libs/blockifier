use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use test_case::test_case;

use super::{assert_consistent_contract_version, REQUIRED_GAS_CALL_CONTRACT_TEST};
use crate::abi::abi_utils::selector_from_name;
use crate::context::ChainInfo;
use crate::execution::call_info::{CallExecution, Retdata};
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::native::utils::NATIVE_GAS_PLACEHOLDER;
use crate::retdata;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{create_calldata, trivial_external_entry_point_new, CairoVersion, BALANCE};

#[test_case(
    FeatureContract::SierraTestContract,
    FeatureContract::SierraTestContract,
    NATIVE_GAS_PLACEHOLDER;
    "Call Contract between two contracts using Native"
)]
#[test_case(
    FeatureContract::SierraTestContract,
    FeatureContract::TestContract(CairoVersion::Cairo1),
    NATIVE_GAS_PLACEHOLDER;
    "Call Contract with caller using Native and callee using VM"
)]
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    FeatureContract::SierraTestContract,
    93430 + NATIVE_GAS_PLACEHOLDER;
    "Call Contract with caller using VM and callee using Native")
]
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    FeatureContract::TestContract(CairoVersion::Cairo1),
    REQUIRED_GAS_CALL_CONTRACT_TEST;
    "Call Contract between two contracts using VM"
)]
fn test_call_contract(
    outer_contract: FeatureContract,
    inner_contract: FeatureContract,
    expected_gas: u64,
) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(outer_contract, 1), (inner_contract, 1)]);

    assert_consistent_contract_version(outer_contract, &state);
    assert_consistent_contract_version(inner_contract, &state);

    let outer_entry_point_selector = selector_from_name("test_call_contract");
    let calldata = create_calldata(
        inner_contract.get_instance_address(0),
        "test_storage_read_write",
        &[
            stark_felt!(405_u16), // Calldata: address.
            stark_felt!(48_u8),   // Calldata: value.
        ],
    );
    let entry_point_call = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata,
        ..trivial_external_entry_point_new(outer_contract)
    };

    pretty_assertions::assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            retdata: retdata![stark_felt!(48_u8)],
            gas_consumed: expected_gas,
            ..CallExecution::default()
        }
    );

    // ensure that the fallback system didn't replace the contract
    assert_consistent_contract_version(outer_contract, &state);
    assert_consistent_contract_version(inner_contract, &state);
}
