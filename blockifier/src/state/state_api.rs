use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::execution::contract_class::ContractClass;
use crate::state::errors::{StateError, StateReaderError};

pub type StateResult<T> = Result<T, StateError>;
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
    ) -> StateReaderResult<StarkFelt>;

    /// Returns the nonce of the given contract instance.
    /// Default: 0 for an uninitialized contract address.
    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateReaderResult<Nonce>;

    /// Returns the class hash of the contract class at the given contract instance.
    /// Default: 0 (uninitialized class hash) for an uninitialized contract address.
    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateReaderResult<ClassHash>;

    /// Returns the contract class of the given class hash.
    fn get_contract_class(&self, class_hash: &ClassHash) -> StateReaderResult<ContractClass>;
}

/// A class defining the API for writing to StarkNet global state.

/// Reader functionality should be delegated to the associated type; which is passed in by
/// dependency-injection.
pub trait State {
    type Reader: StateReader;

    fn get_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<&StarkFelt>;

    /// Sets the storage value under the given key in the given contract instance.
    fn set_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    );

    fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<&Nonce>;

    /// Increments the nonce of the given contract instance.
    fn increment_nonce(&mut self, contract_address: ContractAddress) -> StateResult<()>;

    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<&ClassHash>;

    fn get_contract_class(&mut self, class_hash: &ClassHash) -> StateResult<&ContractClass>;

    // Allocates the given address to the given class hash.
    // Raises an exception if the address is already assigned;
    // meaning: this is a write once action.
    fn set_class_hash_at(
        &mut self,
        contract_address: ContractAddress,
        class_hash: ClassHash,
    ) -> StateResult<()>;
}
