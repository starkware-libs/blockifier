use starknet_api::transaction::Calldata;
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::context::ChainInfo;
use crate::execution::call_info::{CallExecution, Retdata};
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::native::utils::NATIVE_GAS_PLACEHOLDER;
use crate::retdata;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{trivial_external_entry_point_new, CairoVersion, BALANCE};

#[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), 256950; "VM")]
fn test_keccak(test_contract: FeatureContract, expected_gas: u64) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let calldata = Calldata(vec![].into());
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_keccak"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state, None).unwrap().execution,
        CallExecution { gas_consumed: expected_gas, ..CallExecution::from_retdata(retdata![]) }
    );
}
