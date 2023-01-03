use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::errors as cairo_rs_vm_errors;
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::StarknetApiError;
use thiserror::Error;

use crate::general_errors::ConversionError;
use crate::state::errors::StateError;

#[derive(Debug, Error)]
pub enum PreExecutionError {
    #[error("Entry point {0:#?} not found in contract.")]
    EntryPointNotFound(EntryPointSelector),
    #[error(transparent)]
    MemoryError(#[from] cairo_rs_vm_errors::memory_errors::MemoryError),
    #[error(transparent)]
    ProgramError(#[from] cairo_rs::types::errors::program_errors::ProgramError),
    #[error(transparent)]
    RunnerError(Box<cairo_rs_vm_errors::runner_errors::RunnerError>),
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error("Requested contract address {0:?} is not deployed.")]
    UninitializedStorageAddress(ContractAddress),
}

impl From<cairo_rs_vm_errors::runner_errors::RunnerError> for PreExecutionError {
    fn from(error: cairo_rs_vm_errors::runner_errors::RunnerError) -> Self {
        Self::RunnerError(Box::new(error))
    }
}

#[derive(Debug, Error)]
pub enum PostExecutionError {
    #[error(transparent)]
    ConversionError(#[from] ConversionError),
    #[error(transparent)]
    MemoryError(#[from] cairo_rs_vm_errors::memory_errors::MemoryError),
    #[error("{0} validation failed.")]
    SecurityValidationError(String),
    #[error(transparent)]
    VirtualMachineError(#[from] cairo_rs_vm_errors::vm_errors::VirtualMachineError),
}

impl From<cairo_rs_vm_errors::runner_errors::RunnerError> for PostExecutionError {
    fn from(error: cairo_rs_vm_errors::runner_errors::RunnerError) -> Self {
        Self::SecurityValidationError(error.to_string())
    }
}

#[derive(Debug, Error)]
pub enum SyscallExecutionError {
    #[error("Bad syscall_ptr; expected: {expected_ptr:?}, got: {actual_ptr:?}.")]
    BadSyscallPointer { expected_ptr: Relocatable, actual_ptr: Relocatable },
    #[error(transparent)]
    InnerCallExecutionError(#[from] EntryPointExecutionError),
    #[error("Invalid syscall input: {input:?}; {info:}")]
    InvalidSyscallInput { input: StarkFelt, info: String },
    #[error("Invalid syscall selector: {0:?}.")]
    InvalidSyscallSelector(StarkFelt),
    #[error(transparent)]
    MemoryError(#[from] cairo_rs_vm_errors::memory_errors::MemoryError),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error(transparent)]
    VirtualMachineError(#[from] cairo_rs_vm_errors::vm_errors::VirtualMachineError),
}

// TODO(AlonH, 21/12/2022): Reconsider error returned by custom hints with LambdaClass.
// Needed for custom hint implementations (in our case, syscall hints) which must comply with the
// cairo-rs API.
impl From<SyscallExecutionError> for cairo_rs_vm_errors::hint_errors::HintError {
    fn from(error: SyscallExecutionError) -> Self {
        cairo_rs_vm_errors::hint_errors::HintError::CustomHint(error.to_string())
    }
}

#[derive(Debug, Error)]
pub enum VirtualMachineExecutionError {
    #[error(transparent)]
    VirtualMachineError(#[from] cairo_rs_vm_errors::vm_errors::VirtualMachineError),
}

#[derive(Debug, Error)]
pub enum EntryPointExecutionError {
    #[error("Invalid input: {input:?}; {info:}")]
    InvalidExecutionInput { input: StarkFelt, info: String },
    #[error(transparent)]
    PostExecutionError(#[from] PostExecutionError),
    #[error(transparent)]
    PreExecutionError(#[from] PreExecutionError),
    #[error(transparent)]
    StateError(#[from] StateError),
    /// Gathers all errors from running the Cairo VM, excluding hints.
    #[error(transparent)]
    VirtualMachineExecutionError(#[from] VirtualMachineExecutionError),
}
