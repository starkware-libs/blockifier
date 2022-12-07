use cairo_rs::vm::errors::memory_errors::MemoryError;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum EntryPointExecutionError {
    #[error(transparent)]
    VirtualMachineError(Box<VirtualMachineError>),
    #[error(transparent)]
    SyscallExecutionError(#[from] SyscallExecutionError),
}

impl From<VirtualMachineError> for EntryPointExecutionError {
    fn from(error: VirtualMachineError) -> Self {
        Self::VirtualMachineError(Box::new(error))
    }
}

impl From<MemoryError> for EntryPointExecutionError {
    fn from(error: MemoryError) -> Self {
        Self::VirtualMachineError(Box::new(VirtualMachineError::MemoryError(error)))
    }
}

impl From<EntryPointExecutionError> for VirtualMachineError {
    fn from(error: EntryPointExecutionError) -> Self {
        match error {
            EntryPointExecutionError::VirtualMachineError(raw_error) => *raw_error,
            error => VirtualMachineError::CustomHint(error.to_string()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum SyscallExecutionError {
    #[error("Invalid syscall selector: {0:?}")]
    InvalidSyscallSelector([u8; 32]),
}
