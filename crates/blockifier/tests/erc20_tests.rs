// run with:
// cargo test --test erc20_tests --features testing
use std::collections::HashMap;
use std::sync::Arc;

use blockifier::abi::abi_utils::selector_from_name;
use blockifier::block_context::BlockContext;
use blockifier::execution::common_hints::ExecutionMode;
use blockifier::execution::contract_address;
use blockifier::execution::entry_point::{
    CallEntryPoint, ConstructorContext, EntryPointExecutionContext,
};
use blockifier::execution::execution_utils::execute_deployment;
use blockifier::execution::sierra_utils::{felt_to_starkfelt, starkfelt_to_felt};
use blockifier::execution::syscalls::hint_processor::{
    FAILED_TO_CALCULATE_CONTRACT_ADDRESS, FAILED_TO_EXECUTE_CALL,
};
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::State;
use blockifier::test_utils::cached_state::get_erc20_class_hash_mapping;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::{
    erc20_external_entry_point, TEST_ERC20_FULL_CONTRACT_ADDRESS,
    TEST_ERC20_FULL_CONTRACT_CLASS_HASH,
};
use blockifier::transaction::objects::{
    AccountTransactionContext, CurrentAccountTransactionContext,
};
use cairo_native::starknet::SyscallResult;
use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{Calldata, ContractAddressSalt};
use starknet_api::{class_hash, contract_address, patricia_key};
use starknet_types_core::felt::Felt;

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

fn deploy_contract(
    state: &mut dyn State,
    class_hash: Felt,
    contract_address_salt: Felt,
    calldata: &[Felt],
) -> SyscallResult<(Felt, Vec<Felt>)> {
    let deployer_address = ContractAddress::default();

    let class_hash = ClassHash(felt_to_starkfelt(class_hash));

    let wrapper_calldata = Calldata(Arc::new(
        calldata.iter().map(|felt| felt_to_starkfelt(*felt)).collect::<Vec<StarkFelt>>(),
    ));

    let calculated_contract_address = calculate_contract_address(
        ContractAddressSalt(felt_to_starkfelt(contract_address_salt)),
        class_hash,
        &wrapper_calldata,
        deployer_address,
    )
    .map_err(|_| vec![Felt::from_hex(FAILED_TO_CALCULATE_CONTRACT_ADDRESS).unwrap()])?;

    let ctor_context = ConstructorContext {
        class_hash,
        code_address: Some(calculated_contract_address),
        storage_address: calculated_contract_address,
        caller_address: deployer_address,
    };

    let call_info = execute_deployment(
        state,
        &mut Default::default(),
        &mut EntryPointExecutionContext::new(
            &BlockContext::create_for_testing(),
            &AccountTransactionContext::Current(Default::default()),
            ExecutionMode::Execute,
            false,
        )
        .unwrap(),
        ctor_context,
        wrapper_calldata,
        u64::MAX,
    )
    .map_err(|_| vec![Felt::from_hex(FAILED_TO_EXECUTE_CALL).unwrap()])?;

    let return_data =
        call_info.execution.retdata.0[..].iter().map(|felt| starkfelt_to_felt(*felt)).collect();

    let contract_address_felt =
        Felt::from_bytes_be_slice(calculated_contract_address.0.key().bytes());

    Ok((contract_address_felt, return_data))
}

pub fn prepare_erc20_deploy_test_state() -> (ContractAddress, CachedState<DictStateReader>) {
    let mut state = create_erc20_deploy_test_state();

    let class_hash = Felt::from_hex(TEST_ERC20_FULL_CONTRACT_CLASS_HASH).unwrap();

    let (contract_address, _) = deploy_contract(
        &mut state,
        class_hash,
        Felt::from(0),
        &[
            Felt::from(0), // Owner
        ],
    )
    .unwrap();

    let contract_address = ContractAddress(
        PatriciaKey::try_from(StarkHash::from(felt_to_starkfelt(contract_address))).unwrap(),
    );

    (contract_address, state)
}

#[test]
fn should_deploy() {
    let (_contract_address, _state) = prepare_erc20_deploy_test_state();
}

// #[test]
// fn mint_works() {
//     let mut state = create_erc20_deploy_test_state();
//
//     let entry_point_name = "total_supply";
//
//     let calldata = Calldata(Arc::new(vec![]));
//
//     let entry_point_call = CallEntryPoint {
//         calldata,
//         entry_point_selector: selector_from_name(entry_point_name),
//         ..erc20_external_entry_point()
//     };
//
//     let result = entry_point_call.execute_directly(&mut state);
//
//     println!("result: {:?}", result);
//
//     assert!(result.is_ok());
// }
