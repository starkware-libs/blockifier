use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;

use assert_matches::assert_matches;
use rstest::{fixture, rstest};
use starknet_api::core::{
    calculate_contract_address, ClassHash, ContractAddress, Nonce, PatriciaKey,
};
use starknet_api::transaction::{Calldata, ContractAddressSalt, ResourceBoundsMapping};
use starknet_api::{calldata, class_hash, contract_address, felt, patricia_key};

use crate::abi::abi_utils::{get_fee_token_var_address, get_storage_var_address};
use crate::concurrency::test_utils::{
    class_hash, contract_address, safe_versioned_state_for_testing,
};
use crate::concurrency::versioned_state::{
    ThreadSafeVersionedState, VersionedState, VersionedStateProxy,
};
use crate::concurrency::TxIndex;
use crate::context::BlockContext;
use crate::state::cached_state::{
    CachedState, ContractClassMapping, StateMaps, TransactionalState,
};
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader, UpdatableState};
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::deploy_account::deploy_account_tx;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{CairoVersion, NonceManager, BALANCE, DEFAULT_STRK_L1_GAS_PRICE};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::objects::{HasRelatedFeeType, TransactionInfoCreator};
use crate::transaction::test_utils::{l1_resource_bounds, max_resource_bounds};
use crate::transaction::transactions::ExecutableTransaction;
use crate::{compiled_class_hash, deploy_account_tx_args, nonce, storage_key};

#[fixture]
pub fn safe_versioned_state(
    contract_address: ContractAddress,
    class_hash: ClassHash,
) -> ThreadSafeVersionedState<CachedState<DictStateReader>> {
    let init_state = DictStateReader {
        address_to_class_hash: HashMap::from([(contract_address, class_hash)]),
        ..Default::default()
    };
    safe_versioned_state_for_testing(CachedState::new(init_state))
}

#[test]
fn test_versioned_state_proxy() {
    // Test data
    let test_contract = FeatureContract::TestContract(CairoVersion::Cairo0);
    let contract_address = contract_address!("0x1");
    let key = storage_key!(0x10_u8);
    let felt = felt!(13_u8);
    let nonce = nonce!(2_u8);
    let class_hash = class_hash!(27_u8);
    let another_class_hash = class_hash!(28_u8);
    let compiled_class_hash = compiled_class_hash!(29_u8);
    let contract_class = test_contract.get_class();

    // Create the versioned state
    let cached_state = CachedState::from(DictStateReader {
        storage_view: HashMap::from([((contract_address, key), felt)]),
        address_to_nonce: HashMap::from([(contract_address, nonce)]),
        address_to_class_hash: HashMap::from([(contract_address, class_hash)]),
        class_hash_to_compiled_class_hash: HashMap::from([(class_hash, compiled_class_hash)]),
        class_hash_to_class: HashMap::from([(class_hash, contract_class.clone())]),
    });

    let versioned_state = Arc::new(Mutex::new(VersionedState::new(cached_state)));

    let safe_versioned_state = ThreadSafeVersionedState(Arc::clone(&versioned_state));
    let versioned_state_proxys: Vec<VersionedStateProxy<CachedState<DictStateReader>>> =
        (0..20).map(|i| safe_versioned_state.pin_version(i)).collect();

    // Read initial data
    assert_eq!(versioned_state_proxys[5].get_nonce_at(contract_address).unwrap(), nonce);
    assert_eq!(versioned_state_proxys[0].get_nonce_at(contract_address).unwrap(), nonce);
    assert_eq!(versioned_state_proxys[7].get_storage_at(contract_address, key).unwrap(), felt);
    assert_eq!(versioned_state_proxys[2].get_class_hash_at(contract_address).unwrap(), class_hash);
    assert_eq!(
        versioned_state_proxys[5].get_compiled_class_hash(class_hash).unwrap(),
        compiled_class_hash
    );
    assert_eq!(
        versioned_state_proxys[7].get_compiled_contract_class(class_hash).unwrap(),
        contract_class
    );
    assert_matches!(
        versioned_state_proxys[7].get_compiled_contract_class(another_class_hash).unwrap_err(),
        StateError::UndeclaredClassHash(class_hash) if
        another_class_hash == class_hash
    );
    assert!(
        !versioned_state_proxys[0].state().declared_contracts.read(0, another_class_hash).unwrap()
    );

    // Write to the state.
    let new_key = storage_key!(0x11_u8);
    let felt_v3 = felt!(14_u8);
    let nonce_v4 = nonce!(3_u8);
    let class_hash_v7 = class_hash!(28_u8);
    let class_hash_v10 = class_hash!(29_u8);
    let compiled_class_hash_v18 = compiled_class_hash!(30_u8);
    let contract_class_v11 = FeatureContract::TestContract(CairoVersion::Cairo1).get_class();

    versioned_state_proxys[3].state().apply_writes(
        3,
        &StateMaps {
            storage: HashMap::from([((contract_address, new_key), felt_v3)]),
            declared_contracts: HashMap::from([(another_class_hash, true)]),
            ..Default::default()
        },
        &HashMap::from([(another_class_hash, contract_class.clone())]),
    );
    versioned_state_proxys[4].state().apply_writes(
        4,
        &StateMaps { nonces: HashMap::from([(contract_address, nonce_v4)]), ..Default::default() },
        &HashMap::default(),
    );
    versioned_state_proxys[7].state().apply_writes(
        7,
        &StateMaps {
            class_hashes: HashMap::from([(contract_address, class_hash_v7)]),
            ..Default::default()
        },
        &HashMap::default(),
    );
    versioned_state_proxys[10].state().apply_writes(
        10,
        &StateMaps {
            class_hashes: HashMap::from([(contract_address, class_hash_v10)]),
            ..Default::default()
        },
        &HashMap::default(),
    );
    versioned_state_proxys[18].state().apply_writes(
        18,
        &StateMaps {
            compiled_class_hashes: HashMap::from([(class_hash, compiled_class_hash_v18)]),
            ..Default::default()
        },
        &HashMap::default(),
    );
    versioned_state_proxys[11].state().apply_writes(
        11,
        &StateMaps::default(),
        &HashMap::from([(class_hash, contract_class_v11.clone())]),
    );

    // Read the data
    assert_eq!(versioned_state_proxys[2].get_nonce_at(contract_address).unwrap(), nonce);
    assert_eq!(versioned_state_proxys[5].get_nonce_at(contract_address).unwrap(), nonce_v4);
    assert_eq!(versioned_state_proxys[5].get_storage_at(contract_address, key).unwrap(), felt);
    assert_eq!(
        versioned_state_proxys[5].get_storage_at(contract_address, new_key).unwrap(),
        felt_v3
    );
    assert_eq!(versioned_state_proxys[2].get_class_hash_at(contract_address).unwrap(), class_hash);
    assert_eq!(
        versioned_state_proxys[9].get_class_hash_at(contract_address).unwrap(),
        class_hash_v7
    );
    assert!(
        !versioned_state_proxys[0].state().declared_contracts.read(0, another_class_hash).unwrap()
    );
    assert!(
        versioned_state_proxys[4].state().declared_contracts.read(4, another_class_hash).unwrap()
    );
    // Include the writes in the current transaction.
    assert_eq!(
        versioned_state_proxys[10].get_class_hash_at(contract_address).unwrap(),
        class_hash_v10
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

#[rstest]
// Test parallel execution of two transactions that use the same versioned state.
fn test_run_parallel_txs(max_resource_bounds: ResourceBoundsMapping) {
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
    let mut versioned_state_proxy_1 = safe_versioned_state.pin_version(1);
    let mut state_1 = TransactionalState::create_transactional(&mut versioned_state_proxy_1);
    let mut versioned_state_proxy_2 = safe_versioned_state.pin_version(2);
    let mut state_2 = TransactionalState::create_transactional(&mut versioned_state_proxy_2);

    // Prepare transactions
    let deploy_account_tx_1 = deploy_account_tx(
        deploy_account_tx_args! {
            class_hash: account_without_validation.get_class_hash(),
            resource_bounds: l1_resource_bounds(u64::from(!zero_bounds), DEFAULT_STRK_L1_GAS_PRICE),
        },
        &mut NonceManager::default(),
    );
    let account_tx_1 = AccountTransaction::DeployAccount(deploy_account_tx_1);
    let enforce_fee = account_tx_1.create_tx_info().enforce_fee().unwrap();

    let class_hash = grindy_account.get_class_hash();
    let ctor_storage_arg = felt!(1_u8);
    let ctor_grind_arg = felt!(0_u8); // Do not grind in deploy phase.
    let constructor_calldata = calldata![ctor_grind_arg, ctor_storage_arg];
    let deploy_tx_args = deploy_account_tx_args! {
        class_hash,
        resource_bounds: max_resource_bounds,
        constructor_calldata: constructor_calldata.clone(),
    };
    let nonce_manager = &mut NonceManager::default();
    let deploy_account_tx_2 = deploy_account_tx(deploy_tx_args, nonce_manager);
    let account_address = deploy_account_tx_2.contract_address;
    let account_tx_2 = AccountTransaction::DeployAccount(deploy_account_tx_2);
    let tx_context = block_context.to_tx_context(&account_tx_2);
    let fee_type = tx_context.tx_info.fee_type();

    let deployed_account_balance_key = get_fee_token_var_address(account_address);
    let fee_token_address = chain_info.fee_token_address(&fee_type);
    state_2
        .set_storage_at(fee_token_address, deployed_account_balance_key, felt!(BALANCE))
        .unwrap();

    let block_context_1 = block_context.clone();
    let block_context_2 = block_context.clone();
    // Execute transactions
    thread::scope(|s| {
        s.spawn(move || {
            let result = account_tx_1.execute(&mut state_1, &block_context_1, true, true);
            assert_eq!(result.is_err(), enforce_fee);
        });
        s.spawn(move || {
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
    });
}

#[rstest]
fn test_validate_reads(
    contract_address: ContractAddress,
    class_hash: ClassHash,
    safe_versioned_state: ThreadSafeVersionedState<CachedState<DictStateReader>>,
) {
    let storage_key = storage_key!(0x10_u8);

    let mut version_state_proxy = safe_versioned_state.pin_version(1);
    let transactional_state = TransactionalState::create_transactional(&mut version_state_proxy);

    // Validating tx index 0 always succeeds.
    assert!(safe_versioned_state.pin_version(0).validate_reads(&StateMaps::default()));

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

    assert!(transactional_state.cache.borrow().initial_reads.declared_contracts.is_empty());
    assert_matches!(
        transactional_state.get_compiled_contract_class(class_hash),
        Err(StateError::UndeclaredClassHash(err_class_hash)) if
        err_class_hash == class_hash
    );

    assert_eq!(transactional_state.cache.borrow().initial_reads.declared_contracts.len(), 1);

    assert!(
        safe_versioned_state
            .pin_version(1)
            .validate_reads(&transactional_state.cache.borrow().initial_reads)
    );
}

#[rstest]
#[case::storage(
    StateMaps {
        storage: HashMap::from(
            [((contract_address!("0x1"), storage_key!("0x1")), felt!(1_u8))]
        ),
        ..Default::default()
    },
    StateMaps {
        storage: HashMap::from(
            [((contract_address!("0x1"), storage_key!("0x1")), felt!(2_u8))]
        ),
        ..Default::default()
    }
)]
#[case::nonces(
    StateMaps {
        nonces: HashMap::from([(contract_address!("0x1"), nonce!(1_u8))]),
        ..Default::default()
    },
    StateMaps {
        nonces: HashMap::from([(contract_address!("0x1"), nonce!(2_u8))]),
        ..Default::default()
    }
)]
#[case::class_hashes(
    StateMaps {
        class_hashes: HashMap::from([(contract_address!("0x1"), class_hash!(1_u8))]),
        ..Default::default()
    },
    StateMaps {
        class_hashes: HashMap::from([(contract_address!("0x1"), class_hash!(2_u8))]),
        ..Default::default()
    }
)]
#[case::compiled_class_hashes(
    StateMaps {
        compiled_class_hashes: HashMap::from([(class_hash!(1_u8), compiled_class_hash!(1_u8))]),
        ..Default::default()
    },
    StateMaps {
        compiled_class_hashes: HashMap::from([(class_hash!(1_u8), compiled_class_hash!(2_u8))]),
        ..Default::default()
    }
)]
fn test_false_validate_reads(
    #[case] tx_1_reads: StateMaps,
    #[case] tx_0_writes: StateMaps,
    safe_versioned_state: ThreadSafeVersionedState<CachedState<DictStateReader>>,
) {
    let version_state_proxy = safe_versioned_state.pin_version(0);
    version_state_proxy.state().apply_writes(0, &tx_0_writes, &HashMap::default());
    assert!(!safe_versioned_state.pin_version(1).validate_reads(&tx_1_reads));
}

#[rstest]
fn test_false_validate_reads_declared_contracts(
    safe_versioned_state: ThreadSafeVersionedState<CachedState<DictStateReader>>,
) {
    let tx_1_reads = StateMaps {
        declared_contracts: HashMap::from([(class_hash!(1_u8), false)]),
        ..Default::default()
    };
    let tx_0_writes = StateMaps {
        declared_contracts: HashMap::from([(class_hash!(1_u8), true)]),
        ..Default::default()
    };
    let version_state_proxy = safe_versioned_state.pin_version(0);
    let compiled_contract_calss = FeatureContract::TestContract(CairoVersion::Cairo1).get_class();
    let class_hash_to_class = HashMap::from([(class_hash!(1_u8), compiled_contract_calss)]);
    version_state_proxy.state().apply_writes(0, &tx_0_writes, &class_hash_to_class);
    assert!(!safe_versioned_state.pin_version(1).validate_reads(&tx_1_reads));
}

#[rstest]
fn test_apply_writes(
    contract_address: ContractAddress,
    class_hash: ClassHash,
    safe_versioned_state: ThreadSafeVersionedState<CachedState<DictStateReader>>,
) {
    let mut versioned_proxy_states: Vec<VersionedStateProxy<CachedState<DictStateReader>>> =
        (0..2).map(|i| safe_versioned_state.pin_version(i)).collect();
    let mut transactional_states: Vec<
        TransactionalState<'_, VersionedStateProxy<CachedState<DictStateReader>>>,
    > = versioned_proxy_states.iter_mut().map(TransactionalState::create_transactional).collect();

    // Transaction 0 class hash.
    let class_hash_0 = class_hash!(76_u8);
    assert!(transactional_states[0].cache.borrow().writes.class_hashes.is_empty());
    transactional_states[0].set_class_hash_at(contract_address, class_hash_0).unwrap();
    assert_eq!(transactional_states[0].cache.borrow().writes.class_hashes.len(), 1);

    // Transaction 0 contract class.
    let contract_class_0 = FeatureContract::TestContract(CairoVersion::Cairo1).get_class();
    assert!(transactional_states[0].class_hash_to_class.borrow().is_empty());
    transactional_states[0].set_contract_class(class_hash, contract_class_0.clone()).unwrap();
    assert_eq!(transactional_states[0].class_hash_to_class.borrow().len(), 1);

    safe_versioned_state.pin_version(0).apply_writes(
        &transactional_states[0].cache.borrow().writes,
        &transactional_states[0].class_hash_to_class.borrow().clone(),
        &HashMap::default(),
    );
    assert!(transactional_states[1].get_class_hash_at(contract_address).unwrap() == class_hash_0);
    assert!(
        transactional_states[1].get_compiled_contract_class(class_hash).unwrap()
            == contract_class_0
    );
}

#[rstest]
fn test_apply_writes_reexecute_scenario(
    contract_address: ContractAddress,
    class_hash: ClassHash,
    safe_versioned_state: ThreadSafeVersionedState<CachedState<DictStateReader>>,
) {
    let mut versioned_proxy_states: Vec<VersionedStateProxy<CachedState<DictStateReader>>> =
        (0..2).map(|i| safe_versioned_state.pin_version(i)).collect();
    let mut transactional_states: Vec<
        TransactionalState<'_, VersionedStateProxy<CachedState<DictStateReader>>>,
    > = versioned_proxy_states.iter_mut().map(TransactionalState::create_transactional).collect();

    // Transaction 0 class hash.
    let class_hash_0 = class_hash!(76_u8);
    transactional_states[0].set_class_hash_at(contract_address, class_hash_0).unwrap();

    // As transaction 0 hasn't written to the shared state yet, the class hash should not be
    // updated.
    assert!(transactional_states[1].get_class_hash_at(contract_address).unwrap() == class_hash);

    safe_versioned_state.pin_version(0).apply_writes(
        &transactional_states[0].cache.borrow().writes,
        &transactional_states[0].class_hash_to_class.borrow().clone(),
        &HashMap::default(),
    );
    // Although transaction 0 wrote to the shared state, version 1 needs to be re-executed to see
    // the new value (its read value has already been cached).
    assert!(transactional_states[1].get_class_hash_at(contract_address).unwrap() == class_hash);

    // TODO: Use re-execution native util once it's ready.
    // "Re-execute" the transaction.
    let mut versioned_state_proxy = safe_versioned_state.pin_version(1);
    transactional_states[1] = TransactionalState::create_transactional(&mut versioned_state_proxy);
    // The class hash should be updated.
    assert!(transactional_states[1].get_class_hash_at(contract_address).unwrap() == class_hash_0);
}

#[rstest]
fn test_delete_writes(
    #[values(0, 1, 2)] tx_index_to_delete_writes: TxIndex,
    safe_versioned_state: ThreadSafeVersionedState<CachedState<DictStateReader>>,
) {
    let num_of_txs = 3;
    let mut versioned_proxy_states: Vec<VersionedStateProxy<CachedState<DictStateReader>>> =
        (0..num_of_txs).map(|i| safe_versioned_state.pin_version(i)).collect();
    let mut transactional_states: Vec<
        TransactionalState<'_, VersionedStateProxy<CachedState<DictStateReader>>>,
    > = versioned_proxy_states.iter_mut().map(TransactionalState::create_transactional).collect();

    // Setting 2 instances of the contract to ensure `delete_writes` removes information from
    // multiple keys. Class hash values are not checked in this test.
    let contract_addresses = [
        (contract_address!("0x100"), class_hash!(20_u8)),
        (contract_address!("0x200"), class_hash!(21_u8)),
    ];
    let feature_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    for (i, tx_state) in transactional_states.iter_mut().enumerate() {
        // Modify the `cache` member of the CachedState.
        for (contract_address, class_hash) in contract_addresses.iter() {
            tx_state.set_class_hash_at(*contract_address, *class_hash).unwrap();
        }
        // Modify the `class_hash_to_class` member of the CachedState.
        tx_state
            .set_contract_class(feature_contract.get_class_hash(), feature_contract.get_class())
            .unwrap();
        safe_versioned_state.pin_version(i).apply_writes(
            &tx_state.cache.borrow().writes,
            &tx_state.class_hash_to_class.borrow(),
            &HashMap::default(),
        );
    }

    safe_versioned_state.pin_version(tx_index_to_delete_writes).delete_writes(
        &transactional_states[tx_index_to_delete_writes].cache.borrow().writes,
        &transactional_states[tx_index_to_delete_writes].class_hash_to_class.borrow(),
    );

    for tx_index in 0..num_of_txs {
        let should_be_empty = tx_index == tx_index_to_delete_writes;
        assert_eq!(
            safe_versioned_state
                .0
                .lock()
                .unwrap()
                .get_writes_of_index(tx_index)
                .class_hashes
                .is_empty(),
            should_be_empty
        );

        assert_eq!(
            safe_versioned_state
                .0
                .lock()
                .unwrap()
                .compiled_contract_classes
                .get_writes_of_index(tx_index)
                .is_empty(),
            should_be_empty
        );
    }
}

#[rstest]
fn test_delete_writes_completeness(
    safe_versioned_state: ThreadSafeVersionedState<CachedState<DictStateReader>>,
) {
    let feature_contract = FeatureContract::TestContract(CairoVersion::Cairo1);
    let state_maps_writes = StateMaps {
        nonces: HashMap::from([(contract_address!("0x1"), Nonce(felt!(1_u8)))]),
        class_hashes: HashMap::from([(
            contract_address!("0x1"),
            feature_contract.get_class_hash(),
        )]),
        storage: HashMap::from([((contract_address!("0x1"), storage_key!(1_u8)), felt!("0x1"))]),
        compiled_class_hashes: HashMap::from([(
            feature_contract.get_class_hash(),
            compiled_class_hash!(0x1_u16),
        )]),
        declared_contracts: HashMap::from([(feature_contract.get_class_hash(), true)]),
    };
    let class_hash_to_class_writes =
        HashMap::from([(feature_contract.get_class_hash(), feature_contract.get_class())]);

    let tx_index = 0;
    let mut versioned_state_proxy = safe_versioned_state.pin_version(tx_index);

    versioned_state_proxy.apply_writes(
        &state_maps_writes,
        &class_hash_to_class_writes,
        &HashMap::default(),
    );
    assert_eq!(
        safe_versioned_state.0.lock().unwrap().get_writes_of_index(tx_index),
        state_maps_writes
    );
    assert_eq!(
        safe_versioned_state
            .0
            .lock()
            .unwrap()
            .compiled_contract_classes
            .get_writes_of_index(tx_index),
        class_hash_to_class_writes
    );

    versioned_state_proxy.delete_writes(&state_maps_writes, &class_hash_to_class_writes);
    assert_eq!(
        safe_versioned_state.0.lock().unwrap().get_writes_of_index(tx_index),
        StateMaps::default()
    );
    assert_eq!(
        safe_versioned_state
            .0
            .lock()
            .unwrap()
            .compiled_contract_classes
            .get_writes_of_index(tx_index),
        ContractClassMapping::default()
    );
}

#[rstest]
fn test_versioned_proxy_state_flow(
    safe_versioned_state: ThreadSafeVersionedState<CachedState<DictStateReader>>,
) {
    let contract_address = contract_address!("0x1");
    let class_hash = ClassHash(felt!(27_u8));

    let mut versioned_proxy_states: Vec<VersionedStateProxy<CachedState<DictStateReader>>> =
        (0..4).map(|i| safe_versioned_state.pin_version(i)).collect();

    let mut transactional_states = Vec::with_capacity(4);
    for proxy_state in &mut versioned_proxy_states {
        transactional_states.push(TransactionalState::create_transactional(proxy_state));
    }

    // Clients class hash values.
    let class_hash_1 = ClassHash(felt!(76_u8));
    let class_hash_3 = ClassHash(felt!(234_u8));

    transactional_states[1].set_class_hash_at(contract_address, class_hash_1).unwrap();
    transactional_states[3].set_class_hash_at(contract_address, class_hash_3).unwrap();

    // Clients contract class values.
    let contract_class_0 = FeatureContract::TestContract(CairoVersion::Cairo0).get_class();
    let contract_class_2 =
        FeatureContract::AccountWithLongValidate(CairoVersion::Cairo1).get_class();

    transactional_states[0].set_contract_class(class_hash, contract_class_0).unwrap();
    transactional_states[2].set_contract_class(class_hash, contract_class_2.clone()).unwrap();

    // Apply the changes.
    for (i, transactional_state) in transactional_states.iter_mut().enumerate() {
        safe_versioned_state.0.lock().unwrap().apply_writes(
            i,
            &transactional_state.cache.borrow().writes,
            &transactional_state.class_hash_to_class.borrow().clone(),
        );
    }

    // Check the final state.
    for proxy in versioned_proxy_states {
        drop(proxy);
    }
    let modified_block_state = safe_versioned_state
        .into_inner_state()
        .commit_chunk_and_recover_block_state(4, HashMap::new());

    assert!(modified_block_state.get_class_hash_at(contract_address).unwrap() == class_hash_3);
    assert!(
        modified_block_state.get_compiled_contract_class(class_hash).unwrap() == contract_class_2
    );
}
