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
use crate::concurrency::versioned_state_proxy::{
    ThreadSafeVersionedState, VersionedState, VersionedStateProxy,
};
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
    // Test data
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let contract_address = contract_address!("0x1");
    let key = StorageKey(patricia_key!("0x10"));
    let stark_felt = stark_felt!(13_u8);
    let nonce = Nonce(stark_felt!(2_u8));
    let class_hash = ClassHash(stark_felt!(27_u8));
    let compiled_class_hash = CompiledClassHash(stark_felt!(29_u8));
    let contract_class = test_contract.get_class();

    // Create the verioned state
    let cached_state = CachedState::from(DictStateReader {
        storage_view: HashMap::from([((contract_address, key), stark_felt)]),
        address_to_nonce: HashMap::from([(contract_address, nonce)]),
        address_to_class_hash: HashMap::from([(contract_address, class_hash)]),
        class_hash_to_compiled_class_hash: HashMap::from([(class_hash, compiled_class_hash)]),
        class_hash_to_class: HashMap::from([(class_hash, contract_class.clone())]),
    });

    let versioned_state = Arc::new(Mutex::new(VersionedState::new(cached_state)));

    let safe_versioned_state = ThreadSafeVersionedState(Arc::clone(&versioned_state));
    let mut versioned_state_proxys: Vec<VersionedStateProxy<CachedState<DictStateReader>>> =
        (0..20).map(|i| safe_versioned_state.pin_version(i)).collect();

    // Read initial data
    assert_eq!(versioned_state_proxys[5].get_nonce_at(contract_address).unwrap(), nonce);
    assert_eq!(versioned_state_proxys[0].get_nonce_at(contract_address).unwrap(), nonce);
    assert_eq!(
        versioned_state_proxys[7].get_storage_at(contract_address, key).unwrap(),
        stark_felt
    );
    assert_eq!(versioned_state_proxys[2].get_class_hash_at(contract_address).unwrap(), class_hash);
    assert_eq!(
        versioned_state_proxys[5].get_compiled_class_hash(class_hash).unwrap(),
        compiled_class_hash
    );
    assert_eq!(
        versioned_state_proxys[7].get_compiled_contract_class(class_hash).unwrap(),
        contract_class
    );

    // Write to the state.
    let new_key = StorageKey(patricia_key!("0x11"));
    let stark_felt_v3 = stark_felt!(14_u8);
    let nonce_v4 = Nonce(stark_felt!(3_u8));
    let class_hash_v7 = ClassHash(stark_felt!(28_u8));
    let class_hash_v10 = ClassHash(stark_felt!(29_u8));
    let compiled_class_hash_v18 = CompiledClassHash(stark_felt!(30_u8));
    let contract_class_v11 = FeatureContract::TestContract(CairoVersion::Cairo1).get_class();

    versioned_state_proxys[3].set_storage_at(contract_address, new_key, stark_felt_v3).unwrap();
    versioned_state_proxys[4].increment_nonce(contract_address).unwrap();
    versioned_state_proxys[7].set_class_hash_at(contract_address, class_hash_v7).unwrap();
    versioned_state_proxys[10].set_class_hash_at(contract_address, class_hash_v10).unwrap();
    versioned_state_proxys[18]
        .set_compiled_class_hash(class_hash, compiled_class_hash_v18)
        .unwrap();
    versioned_state_proxys[11].set_contract_class(class_hash, contract_class_v11.clone()).unwrap();

    // Read the data
    assert_eq!(versioned_state_proxys[2].get_nonce_at(contract_address).unwrap(), nonce);
    assert_eq!(versioned_state_proxys[5].get_nonce_at(contract_address).unwrap(), nonce_v4);
    assert_eq!(
        versioned_state_proxys[5].get_storage_at(contract_address, key).unwrap(),
        stark_felt
    );
    assert_eq!(
        versioned_state_proxys[5].get_storage_at(contract_address, new_key).unwrap(),
        stark_felt_v3
    );
    assert_eq!(versioned_state_proxys[2].get_class_hash_at(contract_address).unwrap(), class_hash);
    assert_eq!(
        versioned_state_proxys[9].get_class_hash_at(contract_address).unwrap(),
        class_hash_v7
    );
    // Ignore the writes in the current transaction.
    assert_eq!(
        versioned_state_proxys[10].get_class_hash_at(contract_address).unwrap(),
        class_hash_v7
    );
    assert_eq!(
        versioned_state_proxys[2].get_compiled_class_hash(class_hash).unwrap(),
        compiled_class_hash
    );
    assert_eq!(
        versioned_state_proxys[19].get_compiled_class_hash(class_hash).unwrap(),
        compiled_class_hash_v18
    );
    assert_eq!(
        versioned_state_proxys[15].get_compiled_contract_class(class_hash).unwrap(),
        contract_class_v11
    );
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

    let safe_versioned_state = ThreadSafeVersionedState(Arc::clone(&versioned_state));
    let mut state_1 = CachedState::from(safe_versioned_state.pin_version(1));
    let mut state_2 = CachedState::from(safe_versioned_state.pin_version(2));

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
    let thread_handle_1 = thread::spawn(move || {
        let result = account_tx_1.execute(&mut state_1, &block_context_1, true, true);
        assert_eq!(result.is_err(), enforce_fee);
    });

    let thread_handle_2 = thread::spawn(move || {
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

    thread_handle_1.join().unwrap();
    thread_handle_2.join().unwrap();
}

// TODO(Meshi 15/5/24): Move this function to `test_util` file.
// TODO: Allow the creation of VersionedState with different state readers.
fn versioned_state_for_testing(
    contract_address: ContractAddress,
    class_hash: ClassHash,
) -> Arc<Mutex<VersionedState<CachedState<DictStateReader>>>> {
    let mut address_to_class_hash = HashMap::new();
    address_to_class_hash.insert(contract_address, class_hash);

    let cached_state =
        CachedState::from(DictStateReader { address_to_class_hash, ..Default::default() });
    Arc::new(Mutex::new(VersionedState::new(cached_state)))
}

#[test]
fn test_validate_read_set() {
    let contract_address = contract_address!("0x1");
    let storage_key = StorageKey(patricia_key!("0x10"));
    let class_hash = ClassHash(stark_felt!(27_u8));
    let versioned_state = versioned_state_for_testing(contract_address, class_hash);

    let safe_versioned_state = ThreadSafeVersionedState(Arc::clone(&versioned_state));
    let mut transactional_state = CachedState::from(safe_versioned_state.pin_version(1));

    // Validating tx index 0 always succeeds.
    assert!(
        versioned_state
            .lock()
            .unwrap()
            .validate_read_set(0, &transactional_state.cache.borrow().initial_reads)
    );

    assert!(transactional_state.cache.borrow().initial_reads.storage.is_empty());
    transactional_state.get_storage_at(contract_address, storage_key).unwrap();
    assert_eq!(transactional_state.cache.borrow().initial_reads.storage.len(), 1);

    assert!(transactional_state.cache.borrow().initial_reads.nonces.is_empty());
    transactional_state.get_nonce_at(contract_address).unwrap();
    assert_eq!(transactional_state.cache.borrow().initial_reads.nonces.len(), 1);

    assert!(transactional_state.cache.borrow().initial_reads.class_hashes.is_empty());
    transactional_state.get_class_hash_at(contract_address).unwrap();
    assert_eq!(transactional_state.cache.borrow().initial_reads.class_hashes.len(), 1);

    assert!(transactional_state.cache.borrow().initial_reads.compiled_class_hashes.is_empty());
    transactional_state.get_compiled_class_hash(class_hash).unwrap();
    assert_eq!(transactional_state.cache.borrow().initial_reads.compiled_class_hashes.len(), 1);

    transactional_state.get_actual_state_changes().unwrap();
    assert!(
        versioned_state
            .lock()
            .unwrap()
            .validate_read_set(1, &transactional_state.cache.borrow().initial_reads)
    );
}

#[test]
fn test_apply_writes() {
    let contract_address = contract_address!("0x1");
    let class_hash = ClassHash(stark_felt!(27_u8));
    let versioned_state = versioned_state_for_testing(contract_address, class_hash);

    let safe_versioned_state = ThreadSafeVersionedState(Arc::clone(&versioned_state));
    let mut transactional_states: Vec<
        CachedState<VersionedStateProxy<CachedState<DictStateReader>>>,
    > = (0..2).map(|i| CachedState::from(safe_versioned_state.pin_version(i))).collect();

    // Client 0 class hash.
    let class_hash_0 = ClassHash(stark_felt!(76_u8));
    assert!(transactional_states[0].cache.borrow().writes.class_hashes.is_empty());
    transactional_states[0].set_class_hash_at(contract_address, class_hash_0).unwrap();
    assert_eq!(transactional_states[0].cache.borrow().writes.class_hashes.len(), 1);

    versioned_state.lock().unwrap().apply_writes(
        0,
        &transactional_states[0].cache.borrow().writes,
        transactional_states[0].class_hash_to_class.borrow().clone(),
    );
    assert!(transactional_states[1].get_class_hash_at(contract_address).unwrap() == class_hash_0);
}

#[test]
fn test_apply_writes_reexecute_scenario() {
    let contract_address = contract_address!("0x1");
    let init_class_hash = ClassHash(stark_felt!(27_u8));
    let versioned_state = versioned_state_for_testing(contract_address, init_class_hash);

    let safe_versioned_state = ThreadSafeVersionedState(Arc::clone(&versioned_state));
    let mut transactional_states: Vec<
        CachedState<VersionedStateProxy<CachedState<DictStateReader>>>,
    > = (0..2).map(|i| CachedState::from(safe_versioned_state.pin_version(i))).collect();

    // Client 0 class hash.
    let class_hash_0 = ClassHash(stark_felt!(76_u8));
    transactional_states[0].set_class_hash_at(contract_address, class_hash_0).unwrap();

    // As the transaction is not committed, the class hash should not be updated.
    assert!(
        transactional_states[1].get_class_hash_at(contract_address).unwrap() == init_class_hash
    );

    versioned_state.lock().unwrap().apply_writes(
        0,
        &transactional_states[0].cache.borrow().writes,
        transactional_states[0].class_hash_to_class.borrow().clone(),
    );
    // Although it has been committed, version 1 needs to be re-executed to see the new value.
    assert!(
        transactional_states[1].get_class_hash_at(contract_address).unwrap() == init_class_hash
    );

    // Re-execute the transaction.
    transactional_states[1] = CachedState::from(safe_versioned_state.pin_version(1));
    // The class hash should be updated.
    assert!(transactional_states[1].get_class_hash_at(contract_address).unwrap() == class_hash_0);
}
