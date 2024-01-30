// run with:
// cargo test --test erc20_tests --features testing
use std::collections::HashMap;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::execution::entry_point::CallEntryPoint;
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::cached_state::get_erc20_class_hash_mapping;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::{
    create_calldata, erc20_external_entry_point, TEST_ERC20_FULL_CONTRACT_ADDRESS,
    TEST_ERC20_FULL_CONTRACT_CLASS_HASH,
};
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::{class_hash, contract_address, patricia_key, stark_felt};

pub fn create_erc20_deploy_test_state() -> CachedState<DictStateReader> {
    let address_to_class_hash: HashMap<ContractAddress, ClassHash> = HashMap::from([(
        contract_address!(TEST_ERC20_FULL_CONTRACT_ADDRESS),
        class_hash!(TEST_ERC20_FULL_CONTRACT_CLASS_HASH),
    )]);

    CachedState::from(DictStateReader {
        address_to_class_hash,
        class_hash_to_class: get_erc20_class_hash_mapping(),
        ..Default::default()
    })
}

#[test]
fn mint_works() {
    let mut state = create_erc20_deploy_test_state();

    let calldata = create_calldata(
        contract_address!(TEST_ERC20_FULL_CONTRACT_ADDRESS),
        "mint",
        &[
            stark_felt!(405_u16), // Calldata: address.
            stark_felt!(48_u8),   // Calldata: value.
        ],
    );

    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("mint"),
        ..erc20_external_entry_point()
    };

    let result = entry_point_call.execute_directly(&mut state);

    println!("result: {:?}", result);

    assert!(result.is_ok());
}
