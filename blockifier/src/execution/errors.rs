use cairo_rs::types::errors::program_errors::ProgramError;
use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::errors::memory_errors::MemoryError;
use cairo_rs::vm::errors::runner_errors::RunnerError;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use starknet_api::core::EntryPointSelector;
use starknet_api::StarknetApiError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PreExecutionError {
    #[error("Entry point {0:#?} not found in contract.")]
    EntryPointNotFound(EntryPointSelector),
    #[error(transparent)]
    ProgramError(#[from] ProgramError),
    #[error(transparent)]
    RunnerError(Box<RunnerError>),
}

impl From<RunnerError> for PreExecutionError {
    fn from(error: RunnerError) -> Self {
        Self::RunnerError(Box::new(error))
    }
}

#[derive(Debug, Error)]
pub enum PostExecutionError {
    #[error(transparent)]
    VirtualMachineError(#[from] VirtualMachineError),
}

impl From<MemoryError> for PostExecutionError {
    fn from(error: MemoryError) -> Self {
        Self::VirtualMachineError(VirtualMachineError::MemoryError(error))
    }
}

#[derive(Debug, Error)]
pub enum SyscallExecutionError {
    #[error("Bad syscall_ptr, Expected {0:?}, got {1:?}.")]
    BadSyscallPointer(Relocatable, Relocatable),
    #[error(transparent)]
    InnerCallExecutionError(Box<EntryPointExecutionError>),
    #[error("Invalid syscall selector: {0:?}.")]
    InvalidSyscallSelector([u8; 32]),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    VirtualMachineError(#[from] VirtualMachineError),
}

impl From<MemoryError> for SyscallExecutionError {
    fn from(error: MemoryError) -> Self {
        Self::VirtualMachineError(VirtualMachineError::MemoryError(error))
    }
}

impl From<EntryPointExecutionError> for SyscallExecutionError {
    fn from(error: EntryPointExecutionError) -> Self {
        Self::InnerCallExecutionError(Box::new(error))
    }
}

// TODO(AlonH, 21/12/2022): Reconsider error returned by custom hints with LambdaClass.
impl From<SyscallExecutionError> for VirtualMachineError {
    fn from(error: SyscallExecutionError) -> Self {
        match error {
            SyscallExecutionError::VirtualMachineError(raw_error) => raw_error,
            error => VirtualMachineError::CustomHint(error.to_string()),
        }
    }
}

#[derive(Debug, Error)]
pub enum VirtualMachineExecutionError {
    #[error(transparent)]
    VirtualMachineError(#[from] VirtualMachineError),
}

#[derive(Debug, Error)]
pub enum EntryPointExecutionError {
    #[error(transparent)]
    PostExecutionError(#[from] PostExecutionError),
    #[error(transparent)]
    PreExecutionError(#[from] PreExecutionError),
    #[error(transparent)]
    SyscallExecutionError(#[from] SyscallExecutionError),
    /// Gathers all errors from running the Cairo VM, excluding hints.
    #[error(transparent)]
    VirtualMachineExecutionError(#[from] VirtualMachineExecutionError),
}
