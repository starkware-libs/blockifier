use cairo_felt::Felt252;
use cairo_vm::types::errors::math_errors::MathError;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::vm_core::VirtualMachine;
use num_bigint::{BigUint, ToBigUint};
use num_traits::ToPrimitive;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_api::StarknetApiError;
use starknet_crypto::FieldElement;
use thiserror::Error;

use crate::execution::execution_utils::stark_felt_to_felt;
use crate::state::errors::StateError;
use crate::state::state_api::StateReader;

pub type SierraTypeResult<T> = Result<T, SierraTypeError>;

#[derive(Debug, Error)]
pub enum SierraTypeError {
    #[error("Felt {val} is too big to convert to {ty}.")]
    ValueTooLargeForType { val: Felt252, ty: &'static str },
    #[error(transparent)]
    MemoryError(#[from] MemoryError),
    #[error(transparent)]
    MathError(#[from] MathError),
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
}

pub trait SierraType: Sized {
    fn from_memory(vm: &VirtualMachine, ptr: &mut Relocatable) -> SierraTypeResult<Self>;
    fn from_storage(
        state: &mut dyn StateReader,
        contract_address: &ContractAddress,
        key: &StorageKey,
    ) -> SierraTypeResult<Self>;
}

// Utils.
pub fn felt_to_u128(felt: &Felt252) -> Result<u128, SierraTypeError> {
    felt.to_u128()
        .ok_or_else(|| SierraTypeError::ValueTooLargeForType { val: felt.clone(), ty: "u128" })
}

// TODO(barak, 01/10/2023): Move to starknet_api under StorageKey implementation.
pub fn increment_storage_key(key: &StorageKey) -> Result<StorageKey, StarknetApiError> {
    Ok(StorageKey(PatriciaKey::try_from(StarkFelt::from(
        FieldElement::from(*key.0.key()) + FieldElement::ONE,
    ))?))
}

// Implementations.

// We implement the trait SierraType for SierraU128 and not for u128 since it's not guaranteed that
// we will always have only one sierra u128 type. For example, we might have two different fields
// where in one of them each cell is at most 127 bits.
pub struct SierraU128 {
    pub val: u128,
}

impl SierraType for SierraU128 {
    fn from_memory(vm: &VirtualMachine, ptr: &mut Relocatable) -> SierraTypeResult<Self> {
        let val_as_felt = vm.get_integer(*ptr)?;
        *ptr = (*ptr + 1)?;
        Ok(Self { val: felt_to_u128(&val_as_felt)? })
    }

    fn from_storage(
        state: &mut dyn StateReader,
        contract_address: &ContractAddress,
        key: &StorageKey,
    ) -> SierraTypeResult<Self> {
        let val_as_felt = stark_felt_to_felt(state.get_storage_at(*contract_address, *key)?);
        Ok(Self { val: felt_to_u128(&val_as_felt)? })
    }
}

pub struct SierraU256 {
    pub low_val: u128,
    pub high_val: u128,
}

impl SierraU256 {
    // TODO(barak, 01/10/2023): Move to_biguint() to the trait and call it as_value(). Use generics
    // to determine the return value.
    pub fn to_biguint(&self) -> BigUint {
        let u128_to_biguint =
            |val: u128| val.to_biguint().expect("u128 to BigUint conversion shouldn't fail.");
        (u128_to_biguint(self.high_val) << 128) + u128_to_biguint(self.low_val)
    }

    pub fn get_explicit_storage_keys(
        key: StorageKey,
    ) -> Result<(StorageKey, StorageKey), StarknetApiError> {
        // TODO(Dori, 1/10/2023): When a standard representation for large integers is set, there
        // may be a better way to add 1 to the key.
        let high_key = increment_storage_key(&key)?;
        Ok((key, high_key))
    }
}

impl SierraType for SierraU256 {
    fn from_memory(vm: &VirtualMachine, ptr: &mut Relocatable) -> Result<Self, SierraTypeError> {
        let low_val_as_felt = vm.get_integer(*ptr)?;
        *ptr = (*ptr + 1)?;
        let high_val_as_felt = vm.get_integer(*ptr)?;
        *ptr = (*ptr + 1)?;
        Ok(Self {
            low_val: felt_to_u128(&low_val_as_felt)?,
            high_val: felt_to_u128(&high_val_as_felt)?,
        })
    }

    fn from_storage(
        state: &mut dyn StateReader,
        contract_address: &ContractAddress,
        key: &StorageKey,
    ) -> SierraTypeResult<Self> {
        let low_val_as_felt = stark_felt_to_felt(state.get_storage_at(*contract_address, *key)?);
        let high_key = increment_storage_key(key)?;
        let high_val_as_felt =
            stark_felt_to_felt(state.get_storage_at(*contract_address, high_key)?);
        Ok(Self {
            low_val: felt_to_u128(&low_val_as_felt)?,
            high_val: felt_to_u128(&high_val_as_felt)?,
        })
    }
}
