use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::errors::memory_errors::MemoryError;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use starknet_api::StarknetApiError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EntryPointExecutionError {
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    SyscallExecutionError(#[from] SyscallExecutionError),
    #[error(transparent)]
    VirtualMachineError(#[from] VirtualMachineError),
}

impl From<MemoryError> for EntryPointExecutionError {
    fn from(error: MemoryError) -> Self {
        Self::VirtualMachineError(VirtualMachineError::MemoryError(error))
    }
}

// TODO(AlonH, 21/12/2022): Reconsider error returned by custom hints with LambdaClass.
impl From<EntryPointExecutionError> for VirtualMachineError {
    fn from(error: EntryPointExecutionError) -> Self {
        match error {
            EntryPointExecutionError::VirtualMachineError(raw_error) => raw_error,
            error => VirtualMachineError::CustomHint(error.to_string()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum SyscallExecutionError {
    #[error("Invalid syscall selector: {0:?}")]
    InvalidSyscallSelector([u8; 32]),
    #[error("Bad syscall_ptr, Expected {0:?}, got {1:?}.")]
    BadSyscallPointer(Relocatable, Relocatable),
}
