use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::{StateDiff, StorageKey};

use crate::execution::contract_class::ContractClass;
use crate::state::errors::StateError;

pub type StateResult<T> = Result<T, StateError>;

/// A read-only API for accessing StarkNet global state.
///
/// The `self` argument is mutable for flexibility during reads (for example, caching reads),
/// and to allow for the `State` trait below to also be considered a `StateReader`.
pub trait StateReader {
    /// Returns the storage value under the given key in the given contract instance (represented by
    /// its address).
    /// Default: 0 for an uninitialized contract address.
    fn get_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt>;

    /// Returns the nonce of the given contract instance.
    /// Default: 0 for an uninitialized contract address.
    fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce>;

    /// Returns the class hash of the contract class at the given contract instance.
    /// Default: 0 (uninitialized class hash) for an uninitialized contract address.
    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash>;

    /// Returns the contract class of the given class hash.
    fn get_contract_class(&mut self, class_hash: &ClassHash) -> StateResult<ContractClass>;
}

/// A class defining the API for writing to StarkNet global state.
///
/// Reader functionality should be delegated to the associated type; which is passed in by
/// dependency-injection.
pub trait State: StateReader {
    /// Sets the storage value under the given key in the given contract instance.
    fn set_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    );

    /// Increments the nonce of the given contract instance.
    fn increment_nonce(&mut self, contract_address: ContractAddress) -> StateResult<()>;

    /// Allocates the given address to the given class hash.
    /// Raises an exception if the address is already assigned;
    /// meaning: this is a write once action.
    fn set_class_hash_at(
        &mut self,
        contract_address: ContractAddress,
        class_hash: ClassHash,
    ) -> StateResult<()>;

    /// Sets the given contract class under the given class hash.
    fn set_contract_class(
        &mut self,
        class_hash: &ClassHash,
        contract_class: ContractClass,
    ) -> StateResult<()>;

    fn to_state_diff(&self) -> StateDiff;
}
