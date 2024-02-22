use std::sync::mpsc;

use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use super::versioned_storage::Version;
use crate::state::errors::StateError;
use crate::state::state_api::{StateReader, StateResult};

#[cfg(test)]
#[path = "versioned_client_state_test.rs"]
pub mod test;

enum Arg {
    ContractAddress(ContractAddress),
    StorageKey(StorageKey),
    ClassHash(ClassHash),
    Version(Version),
    StarkFelt(StarkFelt),
    Nonce(Nonce),
    CompiledClassHash(CompiledClassHash),
}

#[derive(Debug, Clone, Copy)]
enum AccessType {
    Read,
    Write,
}

impl std::fmt::Display for AccessType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessType::Read => write!(f, "Read"),
            AccessType::Write => write!(f, "Write"),
        }
    }
}

enum StorageType {
    Storage,
    Nonce,
    ClassHash,
    CompiledClassHash,
}

impl std::fmt::Display for StorageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageType::Storage => write!(f, "Storage"),
            StorageType::Nonce => write!(f, "Nonce"),
            StorageType::ClassHash => write!(f, "ClassHash"),
            StorageType::CompiledClassHash => write!(f, "CompiledClassHash"),
        }
    }
}

pub struct VersionedClientState {
    sender: mpsc::Sender<Vec<u8>>,
    receiver: mpsc::Receiver<Vec<u8>>,
    version: Version,
}

impl VersionedClientState {
    pub fn new(
        sender: mpsc::Sender<Vec<u8>>,
        receiver: mpsc::Receiver<Vec<u8>>,
        version: Version,
    ) -> Self {
        VersionedClientState { sender, receiver, version }
    }
}

impl StateReader for VersionedClientState {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        self.send_request::<StarkFelt>(
            AccessType::Read,
            StorageType::Storage,
            &[
                Arg::ContractAddress(contract_address),
                Arg::StorageKey(key),
                Arg::Version(self.version),
            ],
        )
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        self.send_request::<Nonce>(
            AccessType::Read,
            StorageType::Nonce,
            &[Arg::ContractAddress(contract_address), Arg::Version(self.version)],
        )
    }

    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        self.send_request::<ClassHash>(
            AccessType::Read,
            StorageType::ClassHash,
            &[Arg::ContractAddress(contract_address), Arg::Version(self.version)],
        )
    }

    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        self.send_request::<CompiledClassHash>(
            AccessType::Read,
            StorageType::CompiledClassHash,
            &[Arg::ClassHash(class_hash), Arg::Version(self.version)],
        )
    }

    fn get_compiled_contract_class(
        &self,
        class_hash: ClassHash,
    ) -> StateResult<crate::execution::contract_class::ContractClass> {
        let _ = class_hash;
        todo!()
    }
}

impl VersionedClientState {
    fn send_request<T>(
        &self,
        access_type: AccessType,
        storage_type: StorageType,
        args: &[Arg],
    ) -> StateResult<T>
    where
        T: serde::de::DeserializeOwned + Default,
    {
        let mut list: Vec<u8> = access_type.to_string().into_bytes();
        list.extend_from_slice(storage_type.to_string().as_bytes());

        for arg in args {
            match arg {
                Arg::ContractAddress(contract_address) => {
                    list.append(&mut serde_json::to_vec(contract_address).unwrap());
                }
                Arg::StorageKey(storage_key) => {
                    list.append(&mut serde_json::to_vec(storage_key).unwrap());
                }
                Arg::ClassHash(class_hash) => {
                    list.append(&mut serde_json::to_vec(class_hash).unwrap());
                }
                Arg::Version(version) => {
                    list.append(&mut serde_json::to_vec(version).unwrap());
                }
                Arg::StarkFelt(stark_felt) => {
                    list.append(&mut serde_json::to_vec(stark_felt).unwrap());
                }
                Arg::Nonce(nonce) => {
                    list.append(&mut serde_json::to_vec(nonce).unwrap());
                }
                Arg::CompiledClassHash(compiled_class_hash) => {
                    list.append(&mut serde_json::to_vec(compiled_class_hash).unwrap());
                }
            }
        }

        match self.sender.send(list) {
            Ok(_) => match access_type {
                AccessType::Read => {
                    let res = self.receiver.recv().unwrap();
                    let deserialized_struct: T = serde_json::from_slice(&res).unwrap();
                    Ok(deserialized_struct)
                }
                AccessType::Write => Ok(T::default()),
            },
            Err(_) => Err(StateError::StateReadError("Failed to send request".to_string())),
        }
    }

    pub fn set_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) -> StateResult<()> {
        self.send_request::<()>(
            AccessType::Write,
            StorageType::Storage,
            &[
                Arg::ContractAddress(contract_address),
                Arg::StorageKey(key),
                Arg::Version(self.version),
                Arg::StarkFelt(value),
            ],
        )
    }

    pub fn set_nonce_at(&self, contract_address: ContractAddress, nonce: Nonce) -> StateResult<()> {
        self.send_request::<()>(
            AccessType::Write,
            StorageType::Nonce,
            &[
                Arg::ContractAddress(contract_address),
                Arg::Version(self.version),
                Arg::Nonce(nonce),
            ],
        )
    }

    pub fn set_class_hash_at(
        &self,
        contract_address: ContractAddress,
        class_hash: ClassHash,
    ) -> StateResult<()> {
        self.send_request::<()>(
            AccessType::Write,
            StorageType::ClassHash,
            &[
                Arg::ContractAddress(contract_address),
                Arg::Version(self.version),
                Arg::ClassHash(class_hash),
            ],
        )
    }

    pub fn set_compiled_class_hash_at(
        &self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
    ) -> StateResult<()> {
        self.send_request::<()>(
            AccessType::Write,
            StorageType::CompiledClassHash,
            &[
                Arg::ClassHash(class_hash),
                Arg::Version(self.version),
                Arg::CompiledClassHash(compiled_class_hash),
            ],
        )
    }
}
