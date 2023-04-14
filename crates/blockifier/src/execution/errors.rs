use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::errors::{self as cairo_vm_errors};
use num_bigint::{BigInt, TryFromBigIntError};
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::StarknetApiError;
use thiserror::Error;

use crate::state::errors::StateError;

// TODO(AlonH, 21/12/2022): Implement Display for all types that appear in errors.

#[derive(Debug, Error)]
pub enum PreExecutionError {
    #[error("Entry point {0:?} not found in contract.")]
    EntryPointNotFound(EntryPointSelector),
    #[error("Entry point {selector:?} of type {typ:?} is not unique.")]
    DuplicatedEntryPointSelector { selector: EntryPointSelector, typ: EntryPointType },
    #[error("No entry points of type {0:?} found in contract.")]
    NoEntryPointOfTypeFound(EntryPointType),
    #[error(transparent)]
    MemoryError(#[from] cairo_vm_errors::memory_errors::MemoryError),
    #[error(transparent)]
    ProgramError(#[from] cairo_vm::types::errors::program_errors::ProgramError),
    #[error(transparent)]
    RunnerError(Box<cairo_vm_errors::runner_errors::RunnerError>),
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error("Requested contract address {0:?} is not deployed.")]
    UninitializedStorageAddress(ContractAddress),
}

impl From<cairo_vm_errors::runner_errors::RunnerError> for PreExecutionError {
    fn from(error: cairo_vm_errors::runner_errors::RunnerError) -> Self {
        Self::RunnerError(Box::new(error))
    }
}

#[derive(Debug, Error)]
pub enum PostExecutionError {
    #[error(transparent)]
    MathError(#[from] cairo_vm::types::errors::math_errors::MathError),
    #[error(transparent)]
    MemoryError(#[from] cairo_vm_errors::memory_errors::MemoryError),
    #[error(transparent)]
    RetdataSizeTooBig(#[from] TryFromBigIntError<BigInt>),
    #[error("Validation failed: {0}.")]
    SecurityValidationError(String),
    #[error(transparent)]
    VirtualMachineError(#[from] cairo_vm_errors::vm_errors::VirtualMachineError),
}

impl From<cairo_vm_errors::runner_errors::RunnerError> for PostExecutionError {
    fn from(error: cairo_vm_errors::runner_errors::RunnerError) -> Self {
        Self::SecurityValidationError(error.to_string())
    }
}

#[derive(Debug, Error)]
pub enum SyscallExecutionError {
    #[error("Bad syscall_ptr; expected: {expected_ptr:?}, got: {actual_ptr:?}.")]
    BadSyscallPointer { expected_ptr: Relocatable, actual_ptr: Relocatable },
    #[error(transparent)]
    InnerCallExecutionError(#[from] EntryPointExecutionError),
    #[error("Invalid syscall input: {input:?}; {info}")]
    InvalidSyscallInput { input: StarkFelt, info: String },
    #[error("Invalid syscall selector: {0:?}.")]
    InvalidSyscallSelector(StarkFelt),
    #[error(transparent)]
    MathError(#[from] cairo_vm::types::errors::math_errors::MathError),
    #[error(transparent)]
    MemoryError(#[from] cairo_vm_errors::memory_errors::MemoryError),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error(transparent)]
    VirtualMachineError(#[from] cairo_vm_errors::vm_errors::VirtualMachineError),
}

// Needed for custom hint implementations (in our case, syscall hints) which must comply with the
// cairo-rs API.
impl From<SyscallExecutionError> for cairo_vm_errors::hint_errors::HintError {
    fn from(error: SyscallExecutionError) -> Self {
        cairo_vm_errors::hint_errors::HintError::CustomHint(error.to_string())
    }
}

#[derive(Debug, Error)]
pub enum VirtualMachineExecutionError {
    #[error(transparent)]
    CairoRunError(#[from] cairo_vm_errors::cairo_run_errors::CairoRunError),
    #[error(transparent)]
    VirtualMachineError(#[from] cairo_vm_errors::vm_errors::VirtualMachineError),
}

#[derive(Debug, Error)]
pub enum EntryPointExecutionError {
    #[error("Invalid input: {input_descriptor}; {info}")]
    InvalidExecutionInput { input_descriptor: String, info: String },
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

impl EntryPointExecutionError {
    /// Unwrap inner VM exception and return it as a string. If unsuccessful, returns the debug
    /// string of self.
    pub fn try_to_vm_trace(&self) -> String {
        match self {
            EntryPointExecutionError::VirtualMachineExecutionError(
                VirtualMachineExecutionError::CairoRunError(
                    cairo_vm_errors::cairo_run_errors::CairoRunError::VmException(vm_exception),
                ),
            ) => {
                let mut trace_string = format!("Error at pc=0:{}:\n", vm_exception.pc);

                // If inner error is a hint error, show generic text.
                match &vm_exception.inner_exc {
                    VirtualMachineError::Hint(_, _) => {
                        trace_string += "Got an exception while executing a hint."
                    }
                    other_inner_error => trace_string += format!("{}", &other_inner_error).as_str(),
                }

                match &vm_exception.traceback {
                    None => trace_string,
                    Some(traceback) => {
                        // TODO(Dori, 1/5/2023): Once LC add newlines between the 'Unknown location'
                        //   strings, remove the `replace`.
                        trace_string
                            + " "
                            + traceback.replace(")Unknown location", ")\nUnknown location").as_str()
                    }
                }
            }
            _ => format!("{:?}", self),
        }
    }
}
