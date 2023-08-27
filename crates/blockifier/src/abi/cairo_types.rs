use cairo_felt::Felt252;
use cairo_vm::types::errors::math_errors::MathError;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::vm_core::VirtualMachine;
use num_traits::ToPrimitive;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CairoTypeError {
    #[error("Felt {0:?} is too big to convert to {1:?}.")]
    ValueTooLargeForType(Felt252, &'static str),
    #[error(transparent)]
    MemoryError(#[from] MemoryError),
    #[error(transparent)]
    MathError(#[from] MathError),
}

pub trait CairoType: Sized {
    fn from_memory(vm: &VirtualMachine, ptr: &mut Relocatable) -> Result<Self, CairoTypeError>;
}

// Utils.
pub fn felt_to_u128(felt: &Felt252) -> Result<u128, CairoTypeError> {
    felt.to_u128().ok_or_else(|| CairoTypeError::ValueTooLargeForType(felt.clone(), "u128"))
}

// Implementations.
pub struct CairoU128 {
    pub val: u128,
}

impl CairoType for CairoU128 {
    fn from_memory(vm: &VirtualMachine, ptr: &mut Relocatable) -> Result<Self, CairoTypeError> {
        let val_as_felt = vm.get_integer(*ptr)?;
        *ptr = (*ptr + 1)?;
        let val = felt_to_u128(&val_as_felt)?;
        Ok(Self { val })
    }
}
