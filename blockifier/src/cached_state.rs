use std::sync::Arc;

use anyhow::Result;
use starknet_api::{ClassHash, ContractAddress, Nonce, StarkFelt, StorageKey};

/// A read-only API for accessing StarkNet global state.
pub trait StateReader {
    /// Returns the storage value under the given key in the given contract instance (represented by
    /// its address); 0 if the contract address is uninitialized.
    fn get_storage_at(
        &self,
        _contract_address: ContractAddress,
        _key: StorageKey,
    ) -> Result<Arc<StarkFelt>> {
        unimplemented!();
    }

    /// Returns the nonce of the given contract instance;
    /// 0 if the contract address is uninitialized.
    fn get_nonce_at(&self, _contract_address: ContractAddress) -> Result<Arc<Nonce>> {
        unimplemented!();
    }

    /// Returns the class hash of the contract class at the given contract instance;
    /// uninitialized class hash, if the address is unassigned.
    fn get_class_hash_at(&self, _contract_address: ContractAddress) -> Result<Arc<ClassHash>> {
        unimplemented!();
    }
}
