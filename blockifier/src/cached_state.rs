// TODO(Gilad, 1/12/2022) remove anyhow from this file and use thiserror.
use anyhow::Result;
use starknet_api::{ClassHash, ContractAddress, Nonce, StarkFelt, StorageKey};

/// A read-only API for accessing StarkNet global state.
pub trait StateReader {
    /// Returns the storage value under the given key in the given contract instance.
    fn get_storage_at(
        &self,
        _contract_address: ContractAddress,
        _key: StorageKey,
    ) -> Result<&StarkFelt> {
        unimplemented!();
    }

    /// Returns the nonce of the given contract instance (represented by its address).
    fn get_nonce_at(&self, _contract_address: ContractAddress) -> Result<&Nonce> {
        unimplemented!();
    }

    /// Returns the class hash of the contract class at the given address.
    fn get_class_hash_at(&self, _contract_address: ContractAddress) -> Result<&ClassHash> {
        unimplemented!();
    }
}
