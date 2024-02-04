use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;

use starknet_api::core::{
    calculate_contract_address, ClassHash, CompiledClassHash, ContractAddress, Nonce, PatriciaKey,
};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Calldata, ContractAddressSalt, Fee, TransactionVersion};
use starknet_api::{calldata, contract_address, patricia_key, stark_felt};

use crate::abi::abi_utils::{get_fee_token_var_address, get_storage_var_address};
use crate::concurrency::versioned_state_proxy::{ThreadSafeVersionedState, VersionedState};
use crate::context::BlockContext;
use crate::deploy_account_tx_args;
use crate::state::cached_state::CachedState;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::deploy_account::deploy_account_tx;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{CairoVersion, NonceManager, BALANCE, DEFAULT_STRK_L1_GAS_PRICE, MAX_FEE};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::objects::{FeeType, TransactionInfoCreator};
use crate::transaction::test_utils::l1_resource_bounds;
use crate::transaction::transactions::ExecutableTransaction;

#[test]
fn test_versioned_state_proxy() {
    // Test data.
    let contract_address = contract_address!("0x1");
    let key = StorageKey(patricia_key!("0x10"));
    let stark_felt = stark_felt!(13_u8);
    let nonce = Nonce(stark_felt!(2_u8));
    let class_hash = ClassHash(stark_felt!(27_u8));
    let compiled_class_hash = CompiledClassHash(stark_felt!(29_u8));

    // Initialize the versioned state.
    let mut storage_view = HashMap::new();
    storage_view.insert((contract_address, key), stark_felt);
    let mut address_to_nonce = HashMap::new();
    address_to_nonce.insert(contract_address, nonce);
    let mut address_to_class_hash = HashMap::new();
    address_to_class_hash.insert(contract_address, class_hash);
    let mut class_hash_to_compiled_class_hash = HashMap::new();
    class_hash_to_compiled_class_hash.insert(class_hash, compiled_class_hash);

    let cached_state = CachedState::from(DictStateReader {
        storage_view,
        address_to_nonce,
        address_to_class_hash,
        class_hash_to_compiled_class_hash,
        ..Default::default()
    });
    let versioned_state = Arc::new(Mutex::new(VersionedState::new(cached_state)));

    // Preparing two states that reference the same versioned state.
    let versioned_client_state_1 =
        ThreadSafeVersionedState(Arc::clone(&versioned_state)).checkout(1);
    let versioned_client_state_2 =
        ThreadSafeVersionedState(Arc::clone(&versioned_state)).checkout(2);

    // Concurrently reading from both states.
    thread::spawn(move || {
        let request = versioned_client_state_1.get_storage_at(contract_address, key);
        assert!(request.is_ok());
        match request {
            Ok(value) => assert_eq!(value, stark_felt),
            Err(_) => panic!("Request returned an error"),
        }

        let request = versioned_client_state_1.get_class_hash_at(contract_address);
        assert!(request.is_ok());
        match request {
            Ok(value) => assert_eq!(value, class_hash),
            Err(_) => panic!("Request returned an error"),
        }

        let request = versioned_client_state_1.get_nonce_at(contract_address);
        assert!(request.is_ok());
        match request {
            Ok(value) => assert_eq!(value, nonce),
            Err(_) => panic!("Request returned an error"),
        }
    });

    thread::spawn(move || {
        let request = versioned_client_state_2.get_class_hash_at(contract_address);
        assert!(request.is_ok());
        match request {
            Ok(value) => assert_eq!(value, class_hash),
            Err(_) => panic!("Request returned an error"),
        }

        let request = versioned_client_state_2.get_nonce_at(contract_address);
        assert!(request.is_ok());
        match request {
            Ok(value) => assert_eq!(value, nonce),
            Err(_) => panic!("Request returned an error"),
        }

        let request = versioned_client_state_2.get_compiled_class_hash(class_hash);
        assert!(request.is_ok());
        match request {
            Ok(value) => assert_eq!(value, compiled_class_hash),
            Err(_) => panic!("Request returned an error"),
        }
    });
}

#[test]
// Test parallel execution of two transactions that use the same versioned state.
fn test_run_parallel_txs() {
    let block_context = BlockContext::create_for_account_testing();
    let chain_info = &block_context.chain_info;
    let zero_bounds = true;

    // Test Accounts
    let grindy_account = FeatureContract::AccountWithLongValidate(CairoVersion::Cairo0);
    let account_without_validation =
        FeatureContract::AccountWithoutValidations(CairoVersion::Cairo0);

    // Initiate States
    let versioned_state = Arc::new(Mutex::new(VersionedState::new(test_state(
        chain_info,
        BALANCE,
        &[(account_without_validation, 1), (grindy_account, 1)],
    ))));

    let mut state_1 =
        CachedState::from(ThreadSafeVersionedState(Arc::clone(&versioned_state)).checkout(1));
    let mut state_2 =
        CachedState::from(ThreadSafeVersionedState(Arc::clone(&versioned_state)).checkout(2));

    // Prepare transactions
    let deploy_account_tx_1 = deploy_account_tx(
        deploy_account_tx_args! {
            class_hash: account_without_validation.get_class_hash(),
            max_fee: Fee(u128::from(!zero_bounds)),
            resource_bounds: l1_resource_bounds(u64::from(!zero_bounds), DEFAULT_STRK_L1_GAS_PRICE),
            version: TransactionVersion::ONE,
        },
        &mut NonceManager::default(),
    );
    let account_tx_1 = AccountTransaction::DeployAccount(deploy_account_tx_1);
    let enforce_fee = account_tx_1.create_tx_info().enforce_fee().unwrap();

    let class_hash = grindy_account.get_class_hash();
    let ctor_storage_arg = stark_felt!(1_u8);
    let ctor_grind_arg = stark_felt!(0_u8); // Do not grind in deploy phase.
    let constructor_calldata = calldata![ctor_grind_arg, ctor_storage_arg];
    let deploy_tx_args = deploy_account_tx_args! {
        class_hash,
        max_fee: Fee(MAX_FEE),
        constructor_calldata: constructor_calldata.clone(),
    };
    let nonce_manager = &mut NonceManager::default();
    let deploy_account_tx_2 = deploy_account_tx(deploy_tx_args, nonce_manager);
    let account_address = deploy_account_tx_2.contract_address;
    let account_tx_2 = AccountTransaction::DeployAccount(deploy_account_tx_2);

    let deployed_account_balance_key = get_fee_token_var_address(account_address);
    let fee_token_address = chain_info.fee_token_address(&FeeType::Eth);
    state_2
        .set_storage_at(fee_token_address, deployed_account_balance_key, stark_felt!(BALANCE))
        .unwrap();

    let block_context_1 = block_context.clone();
    let block_context_2 = block_context.clone();
    // Execute transactions
    thread::spawn(move || {
        let result = account_tx_1.execute(&mut state_1, &block_context_1, true, true);
        assert_eq!(result.is_err(), enforce_fee);
    });

    thread::spawn(move || {
        account_tx_2.execute(&mut state_2, &block_context_2, true, true).unwrap();

        // Check that the constructor wrote ctor_arg to the storage.
        let storage_key = get_storage_var_address("ctor_arg", &[]);
        let deployed_contract_address = calculate_contract_address(
            ContractAddressSalt::default(),
            class_hash,
            &constructor_calldata,
            ContractAddress::default(),
        )
        .unwrap();
        let read_storage_arg =
            state_2.get_storage_at(deployed_contract_address, storage_key).unwrap();
        assert_eq!(ctor_storage_arg, read_storage_arg);
    });
}
