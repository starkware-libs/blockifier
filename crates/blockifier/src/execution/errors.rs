use cairo_native::error::jit_engine::RunnerError as NativeRunnerError;
use cairo_vm::types::errors::math_errors::MathError;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::errors::runner_errors::RunnerError;
use cairo_vm::vm::errors::trace_errors::TraceError;
use cairo_vm::vm::errors::vm_errors::{VirtualMachineError, HINT_ERROR_STR};
use num_bigint::{BigInt, TryFromBigIntError};
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use thiserror::Error;

use crate::execution::execution_utils::format_panic_data;
use crate::state::errors::StateError;

// TODO(AlonH, 21/12/2022): Implement Display for all types that appear in errors.

#[derive(Debug, Error)]
pub enum PreExecutionError {
    #[error("Entry point {selector:?} of type {typ:?} is not unique.")]
    DuplicatedEntryPointSelector { selector: EntryPointSelector, typ: EntryPointType },
    #[error("Entry point {0:?} not found in contract.")]
    EntryPointNotFound(EntryPointSelector),
    #[error("Fraud attempt blocked.")]
    FraudAttempt,
    #[error("Invalid builtin {0:?}.")]
    InvalidBuiltin(String),
    #[error("The constructor entry point must be named 'constructor'.")]
    InvalidConstructorEntryPointName,
    #[error(transparent)]
    MathError(#[from] MathError),
    #[error(transparent)]
    MemoryError(#[from] MemoryError),
    #[error("No entry points of type {0:?} found in contract.")]
    NoEntryPointOfTypeFound(EntryPointType),
    #[error(transparent)]
    ProgramError(#[from] cairo_vm::types::errors::program_errors::ProgramError),
    #[error(transparent)]
    RunnerError(Box<RunnerError>),
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error("Requested contract address {0:?} is not deployed.")]
    UninitializedStorageAddress(ContractAddress),
}

impl From<RunnerError> for PreExecutionError {
    fn from(error: RunnerError) -> Self {
        Self::RunnerError(Box::new(error))
    }
}

#[derive(Debug, Error)]
pub enum PostExecutionError {
    #[error(transparent)]
    MathError(#[from] cairo_vm::types::errors::math_errors::MathError),
    #[error(transparent)]
    MemoryError(#[from] MemoryError),
    #[error(transparent)]
    RetdataSizeTooBig(#[from] TryFromBigIntError<BigInt>),
    #[error("Validation failed: {0}.")]
    SecurityValidationError(String),
    #[error(transparent)]
    VirtualMachineError(#[from] VirtualMachineError),
    #[error("Malformed return data : {error_message}.")]
    MalformedReturnData { error_message: String },
}

impl From<RunnerError> for PostExecutionError {
    fn from(error: RunnerError) -> Self {
        Self::SecurityValidationError(error.to_string())
    }
}

impl EntryPointExecutionError {
    /// Unwrap inner VM exception and return it as a string. If this is a call_contract exception,
    /// the inner error (inner call errors) will not appear in the string.
    pub fn try_to_vm_trace(&self) -> String {
        match self {
            EntryPointExecutionError::CairoRunError(CairoRunError::VmException(exception)) => {
                let mut trace_string = format!("Error at pc=0:{}:\n", exception.pc);
                let inner_exc_string = &exception.inner_exc.to_string();

                // If this error is the result of call_contract returning in error, we do not want
                // to append inner representation.
                // Otherwise, add the inner representation. Prefer using the error attribute as the
                // description of the error; if it is unavailable, use the inner exception string.
                let outer_call_prefix = format!("{HINT_ERROR_STR}Error in the called contract");
                if inner_exc_string.starts_with(&outer_call_prefix) {
                    trace_string += "Got an exception while executing a hint.";
                } else if let Some(error_attribute) = &exception.error_attr_value {
                    trace_string += error_attribute;
                } else {
                    trace_string += inner_exc_string;
                }

                // Append traceback.
                match &exception.traceback {
                    None => trace_string,
                    Some(traceback) => {
                        // TODO(Dori, 1/5/2023): Once LC add newlines between the 'Unknown location'
                        //   strings, remove the `replace`.
                        format!(
                            "{}\n{}",
                            trace_string,
                            traceback.replace(")Unknown location", ")\nUnknown location").as_str()
                        )
                    }
                }
            }
            _ => self.to_string(),
        }
    }
}

#[derive(Debug, Error)]
pub enum EntryPointExecutionError {
    #[error(transparent)]
    CairoRunError(#[from] CairoRunError),
    #[error("Execution failed. Failure reason: {}.", format_panic_data(.error_data))]
    ExecutionFailed { error_data: Vec<StarkFelt> },
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Invalid input: {input_descriptor}; {info}")]
    InvalidExecutionInput { input_descriptor: String, info: String },
    #[error(transparent)]
    PostExecutionError(#[from] PostExecutionError),
    #[error(transparent)]
    PreExecutionError(#[from] PreExecutionError),
    #[error("Execution failed due to recursion depth exceeded.")]
    RecursionDepthExceeded,
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error(transparent)]
    TraceError(#[from] TraceError),
    /// Gathers all errors from running the Cairo VM, excluding hints.
    #[error("{trace}")]
    VirtualMachineExecutionErrorWithTrace {
        trace: String,
        #[source]
        source: CairoRunError,
    },
    #[error("Native execution error: {info}")]
    NativeExecutionError { info: String },
    #[error("Native unexpected error: {source}")]
    NativeUnexpectedError {
        #[source]
        source: NativeRunnerError,
    },
}

#[derive(Debug, Error)]
pub enum ContractClassError {
    #[error(
        "Sierra program length must be > 0 for Cairo1, and == 0 for Cairo0. Got: \
         {sierra_program_length:?} for contract class version {contract_class_version:?}"
    )]
    ContractClassVersionSierraProgramLengthMismatch {
        contract_class_version: u8,
        sierra_program_length: usize,
    },
}
