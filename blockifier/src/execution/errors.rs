use cairo_rs::types::relocatable::Relocatable;
use starknet_api::core::EntryPointSelector;
use starknet_api::StarknetApiError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PreExecutionError {
    #[error("Entry point {0:#?} not found in contract.")]
    EntryPointNotFound(EntryPointSelector),
    #[error(transparent)]
    ProgramError(#[from] cairo_rs::types::errors::program_errors::ProgramError),
    #[error(transparent)]
    RunnerError(Box<cairo_rs::vm::errors::runner_errors::RunnerError>),
}

impl From<cairo_rs::vm::errors::runner_errors::RunnerError> for PreExecutionError {
    fn from(error: cairo_rs::vm::errors::runner_errors::RunnerError) -> Self {
        Self::RunnerError(Box::new(error))
    }
}

#[derive(Debug, Error)]
pub enum PostExecutionError {
    #[error(transparent)]
    MemoryError(#[from] cairo_rs::vm::errors::memory_errors::MemoryError),
    #[error(transparent)]
    VirtualMachineError(#[from] cairo_rs::vm::errors::vm_errors::VirtualMachineError),
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
    MemoryError(#[from] cairo_rs::vm::errors::memory_errors::MemoryError),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    VirtualMachineError(#[from] cairo_rs::vm::errors::vm_errors::VirtualMachineError),
}

impl From<EntryPointExecutionError> for SyscallExecutionError {
    fn from(error: EntryPointExecutionError) -> Self {
        Self::InnerCallExecutionError(Box::new(error))
    }
}

// TODO(AlonH, 21/12/2022): Reconsider error returned by custom hints with LambdaClass.
impl From<SyscallExecutionError> for cairo_rs::vm::errors::vm_errors::VirtualMachineError {
    fn from(error: SyscallExecutionError) -> Self {
            cairo_rs::vm::errors::vm_errors::VirtualMachineError::CustomHint(error.to_string())
    }
}

#[derive(Debug, Error)]
pub enum VirtualMachineExecutionError {
    #[error(transparent)]
    VirtualMachineError(#[from] cairo_rs::vm::errors::vm_errors::VirtualMachineError),
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
