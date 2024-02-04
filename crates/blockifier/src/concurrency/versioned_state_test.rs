use std::collections::HashMap;

use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::{contract_address, patricia_key, stark_felt};

use crate::concurrency::versioned_state::VersionedState;
use crate::state::cached_state::CachedState;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::CairoVersion;

#[test]
fn test_versioned_state() {
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
    let mut versioned_state = VersionedState::new(CachedState::from(DictStateReader {
        storage_view: HashMap::from([((contract_address, key), stark_felt)]),
        address_to_nonce: HashMap::from([(contract_address, nonce)]),
        address_to_class_hash: HashMap::from([(contract_address, class_hash)]),
        class_hash_to_compiled_class_hash: HashMap::from([(class_hash, compiled_class_hash)]),
        class_hash_to_class: HashMap::from([(class_hash, contract_class.clone())]),
    }));

    // Read initial data
    assert_eq!(versioned_state.get_nonce_at(5, contract_address).unwrap(), nonce);
    assert_eq!(versioned_state.get_nonce_at(0, contract_address).unwrap(), nonce);
    assert_eq!(versioned_state.get_storage_at(7, contract_address, key).unwrap(), stark_felt);
    assert_eq!(versioned_state.get_class_hash_at(2, contract_address).unwrap(), class_hash);
    assert_eq!(
        versioned_state.get_compiled_class_hash(97, class_hash).unwrap(),
        compiled_class_hash
    );
    assert_eq!(
        versioned_state.get_compiled_contract_class(15, class_hash).unwrap(),
        contract_class
    );

    // Write to the state.
    let new_key = StorageKey(patricia_key!("0x11"));
    let stark_felt_v3 = stark_felt!(14_u8);
    let nonce_v4 = Nonce(stark_felt!(3_u8));
    let class_hash_v7 = ClassHash(stark_felt!(28_u8));
    let class_hash_v10 = ClassHash(stark_felt!(29_u8));
    let compiled_class_hash_v21 = CompiledClassHash(stark_felt!(30_u8));
    let contract_class_v11 = FeatureContract::TestContract(CairoVersion::Cairo1).get_class();

    versioned_state.set_storage_at(3, contract_address, new_key, stark_felt_v3);
    versioned_state.set_nonce_at(4, contract_address, nonce_v4);
    versioned_state.set_class_hash_at(7, contract_address, class_hash_v7);
    versioned_state.set_class_hash_at(10, contract_address, class_hash_v10);
    versioned_state.set_compiled_class_hash(21, class_hash, compiled_class_hash_v21);
    versioned_state.set_compiled_contract_class(33, class_hash, contract_class_v11.clone());

    // Read the data
    assert_eq!(versioned_state.get_nonce_at(2, contract_address).unwrap(), nonce);
    assert_eq!(versioned_state.get_nonce_at(5, contract_address).unwrap(), nonce_v4);

    assert_eq!(versioned_state.get_storage_at(5, contract_address, key).unwrap(), stark_felt);
    assert_eq!(
        versioned_state.get_storage_at(5, contract_address, new_key).unwrap(),
        stark_felt_v3
    );

    assert_eq!(versioned_state.get_class_hash_at(2, contract_address).unwrap(), class_hash);
    assert_eq!(versioned_state.get_class_hash_at(9, contract_address).unwrap(), class_hash_v7);
    assert_eq!(versioned_state.get_class_hash_at(10, contract_address).unwrap(), class_hash_v10);

    assert_eq!(
        versioned_state.get_compiled_class_hash(2, class_hash).unwrap(),
        compiled_class_hash
    );
    assert_eq!(
        versioned_state.get_compiled_class_hash(100, class_hash).unwrap(),
        compiled_class_hash_v21
    );
    assert_eq!(
        versioned_state.get_compiled_contract_class(64, class_hash).unwrap(),
        contract_class_v11
    );
}
