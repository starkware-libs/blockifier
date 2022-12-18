use std::rc::Rc;

use anyhow::Result;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use super::errors::StateReaderError;
use crate::execution::contract_class::ContractClass;

pub type StateReaderResult<T> = Result<T, StateReaderError>;

/// A read-only API for accessing StarkNet global state.
pub trait StateReader {
    /// Returns the storage value under the given key in the given contract instance (represented by
    /// its address).
    /// Default: 0 for an uninitialized contract address.
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> Result<StarkFelt>;

    /// Returns the nonce of the given contract instance.
    /// Default: 0 for an uninitialized contract address.
    fn get_nonce_at(&self, contract_address: ContractAddress) -> Result<Nonce>;

    /// Returns the class hash of the contract class at the given contract instance.
    /// Default: 0 (uninitialized class hash) for an uninitialized contract address.
    fn get_class_hash_at(&self, _contract_address: ContractAddress) -> Result<ClassHash> {
        unimplemented!();
    }

    /// Returns the contract class of the given class hash.
    fn get_contract_class(&self, class_hash: &ClassHash) -> StateReaderResult<Rc<ContractClass>>;
}
