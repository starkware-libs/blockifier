use cairo_rs::types::errors::program_errors::ProgramError;
use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::errors::exec_scope_errors::ExecScopeError;
use cairo_rs::vm::errors::memory_errors::MemoryError;
use cairo_rs::vm::errors::runner_errors::RunnerError;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use starknet_api::core::EntryPointSelector;
use starknet_api::StarknetApiError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EntryPointExecutionError {
    #[error(transparent)]
    PostprocessExecutionError(#[from] PostprocessExecutionError),
    #[error(transparent)]
    PreprocessExecutionError(#[from] PreprocessExecutionError),
    #[error(transparent)]
    RunEntryPointError(#[from] RunEntryPointError),
    #[error(transparent)]
    SyscallExecutionError(#[from] SyscallExecutionError),
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
pub enum PreprocessExecutionError {
    #[error("Entry point {0:#?} not found in contract.")]
    EntryPointNotFound(EntryPointSelector),
    #[error(transparent)]
    ProgramError(#[from] ProgramError),
    #[error(transparent)]
    VirtualMachineError(#[from] VirtualMachineError),
}

impl From<RunnerError> for PreprocessExecutionError {
    fn from(error: RunnerError) -> Self {
        Self::VirtualMachineError(VirtualMachineError::RunnerError(error))
    }
}

#[derive(Debug, Error)]
pub enum RunEntryPointError {
    #[error(transparent)]
    VirtualMachineError(#[from] VirtualMachineError),
}

#[derive(Debug, Error)]
pub enum PostprocessExecutionError {
    #[error(transparent)]
    VirtualMachineError(#[from] VirtualMachineError),
}

impl From<MemoryError> for PostprocessExecutionError {
    fn from(error: MemoryError) -> Self {
        Self::VirtualMachineError(VirtualMachineError::MemoryError(error))
    }
}

impl From<ExecScopeError> for PostprocessExecutionError {
    fn from(error: ExecScopeError) -> Self {
        Self::VirtualMachineError(VirtualMachineError::MainScopeError(error))
    }
}
