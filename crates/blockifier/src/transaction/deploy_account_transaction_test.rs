use std::collections::HashMap;

use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, Nonce};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeployAccountTransaction, Fee, TransactionHash,
    TransactionSignature, TransactionVersion,
};
use starknet_api::{calldata, stark_felt};

use crate::abi::abi_utils::get_selector_from_name;
use crate::abi::constants::CONSTRUCTOR_ENTRY_POINT_NAME;
use crate::block_context::BlockContext;
use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::state::cached_state::{CachedState, DictStateReader};
use crate::state::state_api::State;
use crate::test_utils::{
    get_contract_class, ACCOUNT_CONTRACT_PATH, TEST_ACCOUNT_CONTRACT_CLASS_HASH,
};
use crate::transaction::depoloy_account_transaction::execute_tx;
use crate::transaction::objects::AccountTransactionContext;

fn create_test_state() -> CachedState<DictStateReader> {
    let test_account_class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let class_hash_to_class =
        HashMap::from([(test_account_class_hash, get_contract_class(ACCOUNT_CONTRACT_PATH))]);
    CachedState::new(DictStateReader { class_hash_to_class, ..Default::default() })
}

fn get_tested_valid_deploy_account_tx() -> DeployAccountTransaction {
    let class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let contract_address_salt = ContractAddressSalt::default();
    let contract_address = calculate_contract_address(
        contract_address_salt.0,
        class_hash,
        &calldata![],
        ContractAddress::default(),
    )
    .unwrap();

    let deploy_account_tx = DeployAccountTransaction {
        transaction_hash: TransactionHash(StarkHash::default()),
        max_fee: Fee(1),
        version: TransactionVersion(StarkFelt::from(1)),
        signature: TransactionSignature(vec![StarkHash::default()]),
        nonce: Nonce::default(),
        class_hash,
        contract_address,
        contract_address_salt,
        constructor_calldata: calldata![],
    };

    deploy_account_tx
}

// TODO(Noa, 25/01/23): Test DeployAccount with constructor + add negative tests.
#[test]
fn test_deploy_account_tx() {
    let mut state = create_test_state();
    let block_context = BlockContext::get_test_block_context();
    // Extract deploy account transaction fields for testing, as the transaction execution consumes
    // the transaction.
    let deploy_account_tx = get_tested_valid_deploy_account_tx();
    let class_hash = deploy_account_tx.class_hash;
    let deployed_account_address = deploy_account_tx.contract_address;

    let account_tx_context = AccountTransactionContext {
        transaction_hash: deploy_account_tx.transaction_hash,
        max_fee: deploy_account_tx.max_fee,
        version: deploy_account_tx.version,
        signature: deploy_account_tx.signature.clone(),
        nonce: deploy_account_tx.nonce,
        sender_address: deployed_account_address,
    };

    let actual_execution_info =
        execute_tx(deploy_account_tx, &mut state, &block_context, &account_tx_context).unwrap();

    let expected_execute_call_info = CallInfo {
        call: CallEntryPoint {
            class_hash: None,
            entry_point_type: EntryPointType::Constructor,
            entry_point_selector: get_selector_from_name(CONSTRUCTOR_ENTRY_POINT_NAME),
            calldata: calldata![],
            storage_address: deployed_account_address,
            caller_address: ContractAddress::default(),
        },
        ..Default::default()
    };

    // Test execution info result.
    assert_eq!(actual_execution_info, expected_execute_call_info);
    // Check the contract is deployed.
    assert_eq!(*state.get_class_hash_at(deployed_account_address).unwrap(), class_hash);
}
