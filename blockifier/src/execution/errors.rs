use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::errors as cairo_rs_vm_errors;
use starknet_api::core::EntryPointSelector;
use starknet_api::StarknetApiError;
use thiserror::Error;

use crate::state::errors::StateReaderError;

#[derive(Debug, Error)]
pub enum PreExecutionError {
    #[error("Entry point {0:#?} not found in contract.")]
    EntryPointNotFound(EntryPointSelector),
    #[error(transparent)]
    ProgramError(#[from] cairo_rs::types::errors::program_errors::ProgramError),
    #[error(transparent)]
    RunnerError(Box<cairo_rs_vm_errors::runner_errors::RunnerError>),
    #[error(transparent)]
    StateReaderError(#[from] StateReaderError),
}

impl From<cairo_rs_vm_errors::runner_errors::RunnerError> for PreExecutionError {
    fn from(error: cairo_rs_vm_errors::runner_errors::RunnerError) -> Self {
        Self::RunnerError(Box::new(error))
    }
}

#[derive(Debug, Error)]
pub enum PostExecutionError {
    #[error(transparent)]
    MemoryError(#[from] cairo_rs_vm_errors::memory_errors::MemoryError),
    #[error(transparent)]
    VirtualMachineError(#[from] cairo_rs_vm_errors::vm_errors::VirtualMachineError),
}

#[derive(Debug, Error)]
pub enum SyscallExecutionError {
    #[error("Bad syscall_ptr; expected: {expected_ptr:?}, got: {actual_ptr:?}.")]
    BadSyscallPointer { expected_ptr: Relocatable, actual_ptr: Relocatable },
    #[error(transparent)]
    InnerCallExecutionError(Box<EntryPointExecutionError>),
    #[error("Invalid syscall selector: {0:?}.")]
    InvalidSyscallSelector([u8; 32]),
    #[error(transparent)]
    MemoryError(#[from] cairo_rs_vm_errors::memory_errors::MemoryError),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    VirtualMachineError(#[from] cairo_rs_vm_errors::vm_errors::VirtualMachineError),
}

impl From<EntryPointExecutionError> for SyscallExecutionError {
    fn from(error: EntryPointExecutionError) -> Self {
        Self::InnerCallExecutionError(Box::new(error))
    }
}

// TODO(AlonH, 21/12/2022): Reconsider error returned by custom hints with LambdaClass.
// Needed for custom hint implementations (in our case, syscall hints) which must comply with the
// cairo-rs API.
impl From<SyscallExecutionError> for cairo_rs_vm_errors::vm_errors::VirtualMachineError {
    fn from(error: SyscallExecutionError) -> Self {
        cairo_rs_vm_errors::vm_errors::VirtualMachineError::CustomHint(error.to_string())
    }
}

#[derive(Debug, Error)]
pub enum VirtualMachineExecutionError {
    #[error(transparent)]
    VirtualMachineError(#[from] cairo_rs_vm_errors::vm_errors::VirtualMachineError),
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

// TODO(Noa, 30/12/22): Find a better way to implement the desired transitive relation.
impl From<StateReaderError> for EntryPointExecutionError {
    fn from(error: StateReaderError) -> Self {
        let pre_exec_error: PreExecutionError = error.into();
        pre_exec_error.into()
    }
}
