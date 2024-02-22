use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;

use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::{contract_address, patricia_key, stark_felt};

use crate::concurrency::versioned_client_state::VersionedClientState;
use crate::concurrency::versioned_state::VersionedState;
use crate::state::state_api::StateReader;
use crate::test_utils::dict_state_reader::DictStateReader;

#[test]
fn test_versioned_client_state() {
    let contract_address = contract_address!("0x1");
    let key = StorageKey(patricia_key!("0x10"));
    let stark_felt = stark_felt!(13_u8);
    let nonce = Nonce(stark_felt!(2_u8));
    let class_hash = ClassHash(stark_felt!(27_u8));
    let compiled_class_hash = CompiledClassHash(stark_felt!(29_u8));

    let mut storage_view = HashMap::new();
    storage_view.insert((contract_address, key), stark_felt);
    let mut address_to_nonce = HashMap::new();
    address_to_nonce.insert(contract_address, nonce);
    let mut address_to_class_hash = HashMap::new();
    address_to_class_hash.insert(contract_address, class_hash);
    let mut class_hash_to_compiled_class_hash = HashMap::new();
    class_hash_to_compiled_class_hash.insert(class_hash, compiled_class_hash);

    let cached_state = DictStateReader {
        storage_view,
        address_to_nonce,
        address_to_class_hash,
        class_hash_to_compiled_class_hash,
        ..Default::default()
    };
    let versioned_state = Arc::new(Mutex::new(VersionedState::new(cached_state)));

    let versioned_client_state_1 = VersionedClientState::new(1, Arc::clone(&versioned_state));

    let versioned_client_state_2 = VersionedClientState::new(2, Arc::clone(&versioned_state));

    thread::spawn(move || {
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
    });
}
