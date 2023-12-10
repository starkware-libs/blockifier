use rstest::rstest;
use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, ContractAddressSalt};
use starknet_api::{calldata, stark_felt};

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants;
use crate::block_context::BlockContext;
use crate::execution::call_info::{CallExecution, Retdata};
use crate::execution::entry_point::CallEntryPoint;
use crate::retdata;
use crate::state::cached_state::CachedState;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{CairoVersion, BALANCE};

#[rstest]
fn test_calculate_contract_address(#[values(CairoVersion::Cairo0)] cairo_version: CairoVersion) {
    let block_context = &BlockContext::create_for_account_testing();
    let test_contract = FeatureContract::TestContract(cairo_version);
    let mut state = test_state(block_context, BALANCE, &[(test_contract, 1)]);

    // code_address: Some(contract_address),

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
            storage_address: deployer_address,
            initial_gas: constants::INITIAL_GAS_COST,
            ..Default::default()
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
    let class_hash = test_contract.get_class_hash();
    let deployer_address = test_contract.get_instance_address(0);

    // Without constructor.
    let calldata_no_constructor = calldata![
        salt.0,                    // Contract_address_salt.
        class_hash.0,              // Class hash.
        stark_felt!(0_u8),         // Calldata length.
        *deployer_address.0.key()  // deployer_address.
    ];
    run_test(salt, class_hash, &calldata![], calldata_no_constructor, deployer_address, &mut state);

    // With constructor.
    let constructor_calldata = calldata![stark_felt!(1_u8), stark_felt!(1_u8)];
    let calldata = calldata![
        salt.0,                    // Contract_address_salt.
        class_hash.0,              // Class hash.
        stark_felt!(2_u8),         // Calldata length.
        stark_felt!(1_u8),         // Calldata: address.
        stark_felt!(1_u8),         // Calldata: value.
        *deployer_address.0.key()  // deployer_address.
    ];
    run_test(salt, class_hash, &constructor_calldata, calldata, deployer_address, &mut state);
}
