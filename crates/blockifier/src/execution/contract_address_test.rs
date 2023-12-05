use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, ContractAddressSalt};
use starknet_api::{calldata, stark_felt};

use crate::abi::abi_utils::selector_from_name;
use crate::execution::call_info::{CallExecution, Retdata};
use crate::execution::entry_point::CallEntryPoint;
use crate::retdata;
use crate::state::cached_state::CachedState;
use crate::test_utils::cached_state::deprecated_create_test_state;
use crate::test_utils::contracts::{FeatureContract, FeatureContractId};
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::{trivial_external_entry_point, CairoVersion};

#[test]
fn test_calculate_contract_address() {
    let mut state = deprecated_create_test_state();

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
            ..trivial_external_entry_point(CairoVersion::Cairo0)
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
    let test_contract =
        FeatureContract::new(FeatureContractId::TestContract, CairoVersion::Cairo0, 0);

    // Without constructor.
    let calldata_no_constructor = calldata![
        salt.0,                         // Contract_address_salt.
        test_contract.class_hash.0,     // Class hash.
        stark_felt!(0_u8),              // Calldata length.
        *test_contract.address.0.key()  // deployer_address.
    ];
    run_test(
        salt,
        test_contract.class_hash,
        &calldata![],
        calldata_no_constructor,
        test_contract.address,
        &mut state,
    );

    // With constructor.
    let constructor_calldata = calldata![stark_felt!(1_u8), stark_felt!(1_u8)];
    let calldata = calldata![
        salt.0,                         // Contract_address_salt.
        test_contract.class_hash.0,     // Class hash.
        stark_felt!(2_u8),              // Calldata length.
        stark_felt!(1_u8),              // Calldata: address.
        stark_felt!(1_u8),              // Calldata: value.
        *test_contract.address.0.key()  // deployer_address.
    ];
    run_test(
        salt,
        test_contract.class_hash,
        &constructor_calldata,
        calldata,
        test_contract.address,
        &mut state,
    );
}
