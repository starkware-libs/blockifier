use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::abi::abi_utils::get_fee_token_var_address;
use crate::abi::sierra_types::{next_storage_key, SierraU256};
use crate::execution::contract_class::ContractClass;
use crate::execution::execution_utils::stark_felt_to_felt;
use crate::state::cached_state::CommitmentStateDiff;
use crate::state::errors::StateError;
use crate::utils::felt_to_u128;

pub type StateResult<T> = Result<T, StateError>;

// TODO(barak, 01/10/2023): Remove this enum from here once it can be used from starknet_api.
pub enum DataAvailabilityMode {
    L1 = 0,
    L2 = 1,
}

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
    fn get_compiled_contract_class(&mut self, class_hash: &ClassHash)
    -> StateResult<ContractClass>;

    /// Returns the compiled class hash of the given class hash.
    fn get_compiled_class_hash(&mut self, class_hash: ClassHash) -> StateResult<CompiledClassHash>;

    /// Returns the storage value representing the balance (in fee token) at the given address.
    // TODO(Dori, 1/7/2023): When a standard representation for large integers is set, change the
    //    return type to that.
    // TODO(Dori, 1/9/2023): NEW_TOKEN_SUPPORT Determine fee token address based on tx version,
    //   once v3 is introduced.
    fn get_fee_token_balance(
        &mut self,
        contract_address: &ContractAddress,
        fee_token_address: &ContractAddress,
    ) -> Result<SierraU256, StateError> {
        let low_key = get_fee_token_var_address(contract_address);
        let high_key = next_storage_key(&low_key)?;
        let low_as_felt = stark_felt_to_felt(self.get_storage_at(*fee_token_address, low_key)?);
        let high_as_felt = stark_felt_to_felt(self.get_storage_at(*fee_token_address, high_key)?);

        Ok(SierraU256 {
            low_val: felt_to_u128(&low_as_felt)?,
            high_val: felt_to_u128(&high_as_felt)?,
        })
    }
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

    /// Sets the given compiled class hash under the given class hash.
    fn set_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
    ) -> StateResult<()>;

    fn to_state_diff(&mut self) -> CommitmentStateDiff;
}
