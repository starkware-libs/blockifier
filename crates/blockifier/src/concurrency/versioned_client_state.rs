use std::sync::{Arc, Mutex};

use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use super::versioned_state::VersionedState;
use super::versioned_storage::Version;
use crate::execution::contract_class::ContractClass;
use crate::state::errors::StateError;
use crate::state::state_api::{StateReader, StateResult};

#[cfg(test)]
#[path = "versioned_client_state_test.rs"]
pub mod test;

pub struct VersionedClientState<S: StateReader> {
    version: Version,
    state: Arc<Mutex<VersionedState<S>>>,
}

impl<S: StateReader> StateReader for VersionedClientState<S> {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        self.state.lock().unwrap().get_storage_at(self.version, contract_address, key)
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        self.state.lock().unwrap().get_nonce_at(self.version, contract_address)
    }

    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        self.state.lock().unwrap().get_class_hash_at(self.version, contract_address)
    }

    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        self.state.lock().unwrap().get_compiled_class_hash(self.version, class_hash)
    }

    fn get_compiled_contract_class(&self, class_hash: ClassHash) -> StateResult<ContractClass> {
        let contract_class =
            self.state.lock().unwrap().get_compiled_contract_class(self.version, class_hash);
        match contract_class {
            Ok(contract_class) => Ok(contract_class),
            _ => Err(StateError::UndeclaredClassHash(class_hash)),
        }
    }
}

impl<S: StateReader> VersionedClientState<S> {
    pub fn new(version: Version, state: Arc<Mutex<VersionedState<S>>>) -> Self {
        VersionedClientState { version, state }
    }
}
