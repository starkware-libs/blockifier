use std::sync::mpsc;

use serde::{Deserialize, Serialize};
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::{contract_address, patricia_key, stark_felt};

use super::versioned_client_state::AccessType;
use crate::concurrency::versioned_client_state::{StorageType, VersionedClientState};
use crate::concurrency::versioned_state::VersionedState;
use crate::state::cached_state::CachedState;
use crate::state::state_api::StateReader;

// #[cfg(test)]
// #[path = "execution_manager_test.rs"]
// pub mod test;

#[derive(Deserialize, Serialize)]
enum TempArg {
    GetClassHash,
    GetStorage,
    GetCompiledClassHash,
    GetNonce,
    SetClassHash,
    SetStorage,
    SetCompiledClassHash,
    SetNonce,
}

pub struct ExecutionManager {
    versioned_state: VersionedState,
    versioned_clients: Vec<VersionedClientState>,
    client_to_manager_channel: mpsc::Receiver<Vec<u8>>,
    manager_to_client_channels: Vec<mpsc::Sender<Vec<u8>>>,
}

impl ExecutionManager {
    pub fn new(state: &'static CachedState<impl StateReader>, n_workers: usize) -> Self {
        assert!(n_workers > 0);
        let (clients_to_manager_sender, clients_to_manager_receiver) = mpsc::channel();
        let mut versioned_clients = Vec::new();
        let mut manager_to_client_channels = Vec::new();

        for i in 0..n_workers {
            let (sender, receiver) = mpsc::channel();
            let versioned_client =
                VersionedClientState::new(clients_to_manager_sender.clone(), receiver, i as u64);
            versioned_clients.push(versioned_client);
            manager_to_client_channels.push(sender.clone());
        }

        ExecutionManager {
            versioned_state: VersionedState::new(state),
            versioned_clients,
            client_to_manager_channel: clients_to_manager_receiver,
            manager_to_client_channels,
        }
    }

    pub fn get_clients_at_index(&self, i: usize) -> &VersionedClientState {
        assert!(i < self.versioned_clients.len());
        &self.versioned_clients[i]
    }

    fn parse_access_type(&self, bytes: &[u8]) -> Option<AccessType> {
        match bytes {
            b"Read" => Some(AccessType::Read),
            b"Write" => Some(AccessType::Write),
            _ => None,
        }
    }

    fn parse_storage_type(&self, bytes: &[u8]) -> Option<StorageType> {
        match bytes {
            b"Storage" => Some(StorageType::Storage),
            b"Nonce" => Some(StorageType::Nonce),
            b"ClassHash" => Some(StorageType::ClassHash),
            b"CompiledClassHash" => Some(StorageType::CompiledClassHash),
            _ => None,
        }
    }

    fn handle_get_storage_request(&mut self, args: Vec<&str>) {
        assert!(args.len() == 3);
        let contract_address = contract_address!(args[0]);
        let storage_key = StorageKey(patricia_key!(args[1]));
        let version = args[2].parse::<u64>().unwrap();
        let response = self.versioned_state.get_storage_at(contract_address, storage_key, version);
        if response.is_err() {
            return;
        }
        let response = serde_json::to_vec(&response.unwrap()).unwrap();
        let sender = &self.manager_to_client_channels[version as usize];
        let response = sender.send(response);
        assert!(response.is_ok());
    }

    fn handle_get_nonce_request(&mut self, args: Vec<&str>) {
        assert!(args.len() == 2);
        let contract_address = contract_address!(args[0]);
        let version = args[1].parse::<u64>().unwrap();
        let response = self.versioned_state.get_nonce_at(contract_address, version);
        if response.is_err() {
            return;
        }
        let response = serde_json::to_vec(&response.unwrap()).unwrap();
        let sender = &self.manager_to_client_channels[version as usize];
        let response = sender.send(response);
        assert!(response.is_ok());
    }

    fn handle_get_class_hash_request(&mut self, args: Vec<&str>) {
        assert!(args.len() == 2);
        let contract_address = contract_address!(args[0]);
        let version = args[1].parse::<u64>().unwrap();
        let response = self.versioned_state.get_class_hash_at(contract_address, version);
        if response.is_err() {
            return;
        }
        let response = serde_json::to_vec(&response.unwrap()).unwrap();
        let sender = &self.manager_to_client_channels[version as usize];
        let response = sender.send(response);
        assert!(response.is_ok());
    }

    fn handle_get_compiled_class_hash_request(&mut self, args: Vec<&str>) {
        assert!(args.len() == 2);
        let class_hash = ClassHash(stark_felt!(args[0]));
        let version = args[1].parse::<u64>().unwrap();
        let response = self.versioned_state.get_compiled_class_hash_at(class_hash, version);
        if response.is_err() {
            return;
        }
        let response = serde_json::to_vec(&response.unwrap()).unwrap();
        let sender = &self.manager_to_client_channels[version as usize];
        let response = sender.send(response);
        assert!(response.is_ok());
    }

    fn handle_set_storage_request(&mut self, args: Vec<&str>) {
        assert!(args.len() == 4);
        let contract_address = contract_address!(args[0]);
        let storage_key = StorageKey(patricia_key!(args[1]));
        let value = stark_felt!(args[2]);
        let version = args[3].parse::<u64>().unwrap();
        let response =
            self.versioned_state.set_storage_at(contract_address, storage_key, value, version);
        if response.is_err() {
            return;
        }
        let response = serde_json::to_vec(&response.unwrap()).unwrap();
        let sender = &self.manager_to_client_channels[version as usize];
        let response = sender.send(response);
        assert!(response.is_ok());
    }

    fn handle_set_nonce_request(&mut self, args: Vec<&str>) {
        assert!(args.len() == 3);
        let contract_address = contract_address!(args[0]);
        let value = Nonce(stark_felt!(args[1]));
        let version = args[2].parse::<u64>().unwrap();
        let response = self.versioned_state.set_nonce_at(contract_address, value, version);
        if response.is_err() {
            return;
        }
        let response = serde_json::to_vec(&response.unwrap()).unwrap();
        let sender = &self.manager_to_client_channels[version as usize];
        let response = sender.send(response);
        assert!(response.is_ok());
    }

    fn handle_set_class_hash_request(&mut self, args: Vec<&str>) {
        assert!(args.len() == 3);
        let contract_address = contract_address!(args[0]);
        let value = ClassHash(stark_felt!(args[1]));
        let version = args[2].parse::<u64>().unwrap();
        let response = self.versioned_state.set_class_hash_at(contract_address, value, version);
        if response.is_err() {
            return;
        }
        let response = serde_json::to_vec(&response.unwrap()).unwrap();
        let sender = &self.manager_to_client_channels[version as usize];
        let response = sender.send(response);
        assert!(response.is_ok());
    }

    fn handle_set_compiled_class_hash_request(&mut self, args: Vec<&str>) {
        assert!(args.len() == 3);
        let class_hash = ClassHash(stark_felt!(args[0]));
        let value = CompiledClassHash(stark_felt!(args[1]));
        let version = args[2].parse::<u64>().unwrap();
        let response = self.versioned_state.set_compiled_class_hash_at(class_hash, value, version);
        if response.is_err() {
            return;
        }
        let response = serde_json::to_vec(&response.unwrap()).unwrap();
        let sender = &self.manager_to_client_channels[version as usize];
        let response = sender.send(response);
        assert!(response.is_ok());
    }

    pub fn run(mut self) {
        loop {
            let request = self.client_to_manager_channel.recv();
            if request.is_err() {
                break;
            }

            let request = request.unwrap();
            let request_string = String::from_utf8_lossy(&request);
            let parts: Vec<&str> = request_string.split('|').map(|s| s.trim()).collect();
            assert!(parts.len() > 3);
            let access_type = self.parse_access_type(parts[0].as_bytes());
            assert!(access_type.is_some());
            match access_type.unwrap() {
                AccessType::Read => {
                    let storage_type = self.parse_storage_type(parts[1].as_bytes());
                    assert!(storage_type.is_some());
                    match storage_type.unwrap() {
                        StorageType::Storage => {
                            self.handle_get_storage_request(parts[2..].into());
                        }
                        StorageType::Nonce => {
                            self.handle_get_nonce_request(parts[2..].into());
                        }
                        StorageType::ClassHash => {
                            self.handle_get_class_hash_request(parts[2..].into());
                        }
                        StorageType::CompiledClassHash => {
                            self.handle_get_compiled_class_hash_request(parts[2..].into());
                        }
                    }
                }
                AccessType::Write => {
                    let storage_type = self.parse_storage_type(parts[1].as_bytes());
                    assert!(storage_type.is_some());
                    match storage_type.unwrap() {
                        StorageType::Storage => {
                            self.handle_set_storage_request(parts[2..].into());
                        }
                        StorageType::Nonce => {
                            self.handle_set_nonce_request(parts[2..].into());
                        }
                        StorageType::ClassHash => {
                            self.handle_set_class_hash_request(parts[2..].into());
                        }
                        StorageType::CompiledClassHash => {
                            self.handle_set_compiled_class_hash_request(parts[2..].into());
                        }
                    }
                }
            }
        }
    }
}
