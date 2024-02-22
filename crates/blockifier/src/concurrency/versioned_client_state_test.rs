use std::sync::mpsc;

use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::{contract_address, patricia_key, stark_felt};

use crate::concurrency::versioned_client_state::VersionedClientState;
use crate::state::state_api::StateReader;

#[test]
fn test_versioned_client_state() {
    let (client_1_to_manager_sender, client_1_to_manager_receiver) = mpsc::channel();
    let (manager_to_client_1_sender, manager_to_client_1_receiver) = mpsc::channel();

    let versioned_client_1_state =
        VersionedClientState::new(client_1_to_manager_sender, manager_to_client_1_receiver, 1);

    let contract_address = contract_address!("0x1234");
    let class_hash = ClassHash(stark_felt!(42_u8));
    let request = versioned_client_1_state.set_class_hash_at(contract_address, class_hash);
    assert!(request.is_ok());
    assert!(client_1_to_manager_receiver.recv().is_ok());

    let response = manager_to_client_1_sender.send(serde_json::to_vec(&class_hash).unwrap());
    assert!(response.is_ok());

    let request = versioned_client_1_state.get_class_hash_at(contract_address);
    assert!(request.is_ok());
    let response = client_1_to_manager_receiver.recv();
    assert!(response.is_ok());
}
