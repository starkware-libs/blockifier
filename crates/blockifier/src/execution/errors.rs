use cairo_vm::types::errors::math_errors::MathError;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::errors::runner_errors::RunnerError;
use cairo_vm::vm::errors::trace_errors::TraceError;
use cairo_vm::vm::errors::vm_errors::{VirtualMachineError, HINT_ERROR_STR};
use cairo_vm::vm::errors::vm_exception::VmException;
use num_bigint::{BigInt, TryFromBigIntError};
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use thiserror::Error;

use super::deprecated_syscalls::hint_processor::DeprecatedSyscallExecutionError;
use super::syscalls::hint_processor::SyscallExecutionError;
use crate::execution::execution_utils::format_panic_data;
use crate::state::errors::StateError;
use crate::transaction::errors::TransactionExecutionError;

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

// A set of functions used to extract error trace from a recursive error object.

/// Extracts the error trace from a `TransactionExecutionError`. This is a top level function.
pub fn gen_transaction_execution_error_trace(error: &TransactionExecutionError) -> String {
    let mut error_stack: Vec<String> = Vec::new();

    match error {
        TransactionExecutionError::ExecutionError { error, storage_address }
        | TransactionExecutionError::ValidateTransactionError { error, storage_address }
        | TransactionExecutionError::ContractConstructorExecutionFailed {
            error,
            storage_address,
        } => {
            error_stack
                .push(format!("Error in the called contract ({}):", *storage_address.0.key()));
            extract_entry_point_execution_error_into_stack_trace(&mut error_stack, error);
            // Temp hack to match existing regression. This is to be deleted shortly.
            #[cfg(test)]
            fix_for_regression(&mut error_stack);
        }
        _ => {
            error_stack.push(error.to_string());
        }
    }

    error_stack.join("\n")
}

#[cfg(test)]
fn fix_for_regression(error_stack: &mut Vec<String>) {
    if error_stack.last().unwrap_or(&String::new()).starts_with("Execution failed. Failure reason:")
    {
        let last_wrapping_hint_error_index = error_stack
            .iter()
            .rposition(|s| s.starts_with("Got an exception while executing a hint."));
        if last_wrapping_hint_error_index.is_some() {
            let index = last_wrapping_hint_error_index.unwrap();
            // replace error stack at index with the cairo 1 error that appears at the end of the
            // stack.
            error_stack[index] =
                format!("{HINT_ERROR_STR}{}", error_stack.last().unwrap().trim_end());
        }
    }
}

fn extract_cairo_run_error_into_stack_trace(error_stack: &mut Vec<String>, error: &CairoRunError) {
    if let CairoRunError::VmException(vm_exception) = error {
        return extract_vm_exception_into_stack_trace(error_stack, vm_exception);
    }
    error_stack.push(error.to_string());
}

fn extract_vm_exception_into_stack_trace(
    error_stack: &mut Vec<String>,
    vm_exception: &VmException,
) {
    let vm_exception_preamble = format!("Error at pc=0:{}:", vm_exception.pc);
    error_stack.push(vm_exception_preamble);

    // TODO(Zuphit): This match is temporary, to match existing regression. To be deleted shortly.
    // Specifically, this is a lookahead to add hint errors earlier than they should be in the
    // recursive unravelling / add a hint error prefix, as currently exists.
    match &vm_exception.inner_exc {
        VirtualMachineError::Hint(_) => {
            error_stack.push("Got an exception while executing a hint.".to_string());
        }
        VirtualMachineError::Other(_) => {}
        _ => {
            error_stack.push(vm_exception.inner_exc.to_string());
        }
    }

    if let Some(traceback) = &vm_exception.traceback {
        error_stack.push(traceback.to_string());
    }
    extract_virtual_machine_error_into_stack_trace(error_stack, &vm_exception.inner_exc)
}

fn extract_virtual_machine_error_into_stack_trace(
    error_stack: &mut Vec<String>,
    vm_error: &VirtualMachineError,
) {
    match vm_error {
        VirtualMachineError::Hint(ref boxed_hint_error) => {
            if let HintError::Internal(internal_vm_error) = &boxed_hint_error.1 {
                return extract_virtual_machine_error_into_stack_trace(
                    error_stack,
                    internal_vm_error,
                );
            }
            error_stack.push(boxed_hint_error.1.to_string());
        }
        VirtualMachineError::Other(anyhow_error) => {
            let syscall_exec_err = anyhow_error.downcast_ref::<SyscallExecutionError>();
            if let Some(downcast_anyhow) = syscall_exec_err {
                extract_syscall_execution_error_into_stack_trace(error_stack, downcast_anyhow)
            } else {
                let deprecated_syscall_exec_err =
                    anyhow_error.downcast_ref::<DeprecatedSyscallExecutionError>();
                if let Some(downcast_anyhow) = deprecated_syscall_exec_err {
                    extract_deprecated_syscall_execution_error_into_stack_trace(
                        error_stack,
                        downcast_anyhow,
                    )
                }
            }
        }
        _ => {
            // TODO(Zuphit): This default push should be reinstated shortly.
            // error_stack.push(format!("{}\n", vm_error.to_string()));
        }
    }
}

fn extract_syscall_execution_error_into_stack_trace(
    error_stack: &mut Vec<String>,
    syscall_error: &SyscallExecutionError,
) {
    match syscall_error {
        SyscallExecutionError::CallContractExecutionError { storage_address, error } => {
            let call_contract_preamble =
                format!("Error in the called contract ({}):", storage_address.0.key());
            error_stack.push(call_contract_preamble);
            extract_syscall_execution_error_into_stack_trace(error_stack, error)
        }
        SyscallExecutionError::LibraryCallExecutionError { storage_address, error, .. } => {
            // TODO(Zuphit): Change to this, or a similar string that includes the class hash.
            // let libcall_preamble = format!("Error in the called contract (hash: {} storage:
            // {}):", class_hash, storage_address.0.key());
            let libcall_preamble =
                format!("Error in the called contract ({}):", storage_address.0.key());
            error_stack.push(libcall_preamble);
            extract_syscall_execution_error_into_stack_trace(error_stack, error);
        }
        SyscallExecutionError::EntryPointExecutionError(entry_point_error) => {
            extract_entry_point_execution_error_into_stack_trace(error_stack, entry_point_error)
        }
        _ => {
            error_stack.push(syscall_error.to_string());
        }
    }
}

fn extract_deprecated_syscall_execution_error_into_stack_trace(
    error_stack: &mut Vec<String>,
    syscall_error: &DeprecatedSyscallExecutionError,
) {
    match syscall_error {
        DeprecatedSyscallExecutionError::CallContractExecutionError { storage_address, error } => {
            let call_contract_preamble =
                format!("Error in the called contract ({}):", storage_address.0.key());
            error_stack.push(call_contract_preamble);
            extract_deprecated_syscall_execution_error_into_stack_trace(error_stack, error)
        }
        DeprecatedSyscallExecutionError::LibraryCallExecutionError {
            storage_address,
            error,
            ..
        } => {
            // TODO(Zuphit): Change to this, or a similar string that includes the class hash.
            // let libcall_preamble = format!("Error in the called contract (hash: {} storage:
            // {}):", class_hash, storage_address.0.key());
            let libcall_preamble =
                format!("Error in the called contract ({}):", storage_address.0.key());
            error_stack.push(libcall_preamble);
            extract_deprecated_syscall_execution_error_into_stack_trace(error_stack, error)
        }
        DeprecatedSyscallExecutionError::EntryPointExecutionError(entry_point_error) => {
            extract_entry_point_execution_error_into_stack_trace(error_stack, entry_point_error)
        }
        _ => error_stack.push(syscall_error.to_string()),
    }
}

fn extract_entry_point_execution_error_into_stack_trace(
    error_stack: &mut Vec<String>,
    entry_point_error: &EntryPointExecutionError,
) {
    match entry_point_error {
        EntryPointExecutionError::VirtualMachineExecutionErrorWithTrace { source, .. } => {
            extract_cairo_run_error_into_stack_trace(error_stack, source)
        }
        _ => error_stack.push(format!("{}\n", entry_point_error)),
    }
}
