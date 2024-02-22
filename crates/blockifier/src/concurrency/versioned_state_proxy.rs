use std::sync::{Arc, Mutex};

use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::concurrency::versioned_state::VersionedState;
use crate::concurrency::Version;
use crate::execution::contract_class::ContractClass;
use crate::state::errors::StateError;
use crate::state::state_api::{StateReader, StateResult};

#[cfg(test)]
#[path = "versioned_state_proxy_test.rs"]
pub mod test;

const LOCK_ERR_MESSAGE: &str = "Failed to acquire lock.";

pub struct VersionedStateProxy<S: StateReader> {
    version: Version,
    state: Arc<Mutex<VersionedState<S>>>,
}

impl<S: StateReader> StateReader for VersionedStateProxy<S> {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        self.state.lock().expect(LOCK_ERR_MESSAGE).get_storage_at(
            self.version,
            contract_address,
            key,
        )
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        self.state.lock().expect(LOCK_ERR_MESSAGE).get_nonce_at(self.version, contract_address)
    }

    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        self.state.lock().expect(LOCK_ERR_MESSAGE).get_class_hash_at(self.version, contract_address)
    }

    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        self.state.lock().expect(LOCK_ERR_MESSAGE).get_compiled_class_hash(self.version, class_hash)
    }

    fn get_compiled_contract_class(&self, class_hash: ClassHash) -> StateResult<ContractClass> {
        let contract_class = self
            .state
            .lock()
            .expect(LOCK_ERR_MESSAGE)
            .get_compiled_contract_class(self.version, class_hash);
        match contract_class {
            Ok(contract_class) => Ok(contract_class),
            _ => Err(StateError::UndeclaredClassHash(class_hash)),
        }
    }
}

impl<S: StateReader> VersionedStateProxy<S> {
    pub fn new(version: Version, state: Arc<Mutex<VersionedState<S>>>) -> Self {
        VersionedStateProxy { version, state }
    }
}
