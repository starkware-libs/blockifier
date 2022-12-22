use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::shash;
use starknet_api::transaction::Calldata;

use crate::abi::abi_utils::get_selector_from_name;
use crate::execution::contract_address::calculate_contract_address;
use crate::execution::entry_point::{CallEntryPoint, CallExecution, Retdata};
use crate::state::cached_state::{CachedState, DictStateReader};
use crate::test_utils::{
    create_test_state, trivial_external_entry_point, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS,
};

#[test]
fn test_contract_address() {
    let mut state = create_test_state();

    fn run_test(
        salt: StarkFelt,
        class_hash: ClassHash,
        constructor_calldata: &Calldata,
        calldata: Calldata,
        deployer_address: ContractAddress,
        state: &mut CachedState<DictStateReader>,
    ) {
        let entry_point_call = CallEntryPoint {
            calldata,
            entry_point_selector: get_selector_from_name("test_contract_address"),
            ..trivial_external_entry_point()
        };
        let contract_address =
            calculate_contract_address(salt, class_hash, constructor_calldata, deployer_address)
                .unwrap();

        assert_eq!(
            entry_point_call.execute(state).unwrap().execution,
            CallExecution { retdata: Retdata(vec![*contract_address.0.key()].into()) }
        );
    }

    let salt = shash!(1);
    let class_hash = ClassHash(shash!(TEST_CLASS_HASH));
    let deployer_address = ContractAddress::try_from(shash!(TEST_CONTRACT_ADDRESS)).unwrap();

    // Without constructor
    let calldata_no_constructor = Calldata(
        vec![
            salt,                      // Contract_address_salt.
            class_hash.0,              // Class hash.
            shash!(0),                 // Calldata length.
            *deployer_address.0.key(), // deployer_address.
        ]
        .into(),
    );
    run_test(
        salt,
        class_hash,
        &Calldata(vec![].into()),
        calldata_no_constructor,
        deployer_address,
        &mut state,
    );

    // With construtor
    let constructor_calldata = Calldata(vec![shash!(1), shash!(1)].into());
    let mut calldata_vec = vec![
        salt,                      // Contract_address_salt.
        class_hash.0,              // Class hash.
        shash!(2),                 // Calldata length.
        shash!(1),                 // Calldata: address.
        shash!(1),                 // Calldata: value.
        *deployer_address.0.key(), // deployer_address.
    ];

    let calldata = Calldata(calldata_vec.clone().into());
    run_test(salt, class_hash, &constructor_calldata, calldata, deployer_address, &mut state);

    // deployer_address = 0
    calldata_vec.pop();
    calldata_vec.push(*ContractAddress::default().0.key());
    run_test(
        salt,
        class_hash,
        &constructor_calldata,
        Calldata(calldata_vec.into()),
        ContractAddress::default(),
        &mut state,
    );
}
