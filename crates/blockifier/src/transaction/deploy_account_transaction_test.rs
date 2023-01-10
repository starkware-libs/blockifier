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
    create_test_state_util, ACCOUNT_CONTRACT_PATH, TEST_ACCOUNT_CONTRACT_ADDRESS,
    TEST_ACCOUNT_CONTRACT_CLASS_HASH,
};
use crate::transaction::execute_transaction::ExecuteTransaction;
use crate::transaction::objects::AccountTransactionContext;

fn create_test_state() -> CachedState<DictStateReader> {
    create_test_state_util(
        TEST_ACCOUNT_CONTRACT_CLASS_HASH,
        ACCOUNT_CONTRACT_PATH,
        // A random address that is unlikely to be equal to the result of
        // calculate_contract_address().
        TEST_ACCOUNT_CONTRACT_ADDRESS,
    )
}

fn get_tested_valid_deploy_account_tx() -> DeployAccountTransaction {
    let class_hash = ClassHash(stark_felt!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));
    let contract_address_salt = ContractAddressSalt::default();
    let contract_address = calculate_contract_address(
        contract_address_salt,
        class_hash,
        &calldata![],
        ContractAddress::default(),
    )
    .unwrap();

    DeployAccountTransaction {
        transaction_hash: TransactionHash(StarkHash::default()),
        max_fee: Fee(1),
        version: TransactionVersion(StarkFelt::from(1)),
        signature: TransactionSignature(vec![StarkHash::default()]),
        nonce: Nonce::default(),
        class_hash,
        contract_address,
        contract_address_salt,
        constructor_calldata: calldata![],
    }
}

// TODO(Noa, 25/01/23): Test DeployAccount with constructor + add negative tests.
#[test]
fn test_deploy_account_tx() {
    let mut state = create_test_state();
    let block_context = BlockContext::create_for_testing();
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
        deploy_account_tx.execute_tx(&mut state, &block_context, &account_tx_context).unwrap();

    let expected_execute_call_info = CallInfo {
        call: CallEntryPoint {
            entry_point_type: EntryPointType::Constructor,
            entry_point_selector: get_selector_from_name(CONSTRUCTOR_ENTRY_POINT_NAME),
            storage_address: deployed_account_address,
            ..Default::default()
        },
        ..Default::default()
    };

    // Test execution info result.
    assert_eq!(actual_execution_info, expected_execute_call_info);
    // Check the contract is deployed.
    assert_eq!(*state.get_class_hash_at(deployed_account_address).unwrap(), class_hash);
}
