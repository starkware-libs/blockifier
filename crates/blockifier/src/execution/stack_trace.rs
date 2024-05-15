use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::errors::vm_exception::VmException;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};

use super::deprecated_syscalls::hint_processor::DeprecatedSyscallExecutionError;
use super::syscalls::hint_processor::SyscallExecutionError;
use crate::execution::errors::{ConstructorEntryPointExecutionError, EntryPointExecutionError};
use crate::transaction::errors::TransactionExecutionError;

type ErrorStack = Vec<String>;

pub const TRACE_LENGTH_CAP: usize = 15000;
pub const TRACE_EXTRA_CHARS_SLACK: usize = 100;

fn finalize_error_stack(error_stack: &ErrorStack) -> String {
    let error_stack_str = error_stack.join("\n");

    // When the trace string is too long, trim it in a way that keeps both the beginning and end.
    if error_stack_str.len() > TRACE_LENGTH_CAP + TRACE_EXTRA_CHARS_SLACK {
        error_stack_str[..(TRACE_LENGTH_CAP / 2)].to_string()
            + "\n\n...\n\n"
            + &error_stack_str[(error_stack_str.len() - TRACE_LENGTH_CAP / 2)..]
    } else {
        error_stack_str
    }
}

/// Extracts the error trace from a `TransactionExecutionError`. This is a top level function.
pub fn gen_transaction_execution_error_trace(error: &TransactionExecutionError) -> String {
    let error_stack = match error {
        TransactionExecutionError::ExecutionError {
            error,
            class_hash,
            storage_address,
            selector,
        }
        | TransactionExecutionError::ValidateTransactionError {
            error,
            class_hash,
            storage_address,
            selector,
        } => gen_error_trace_from_entry_point_error(
            error,
            storage_address,
            class_hash,
            Some(selector),
            false,
        ),
        TransactionExecutionError::ContractConstructorExecutionFailed(
            ConstructorEntryPointExecutionError::ExecutionError {
                error,
                class_hash,
                contract_address: storage_address,
                constructor_selector,
            },
        ) => gen_error_trace_from_entry_point_error(
            error,
            storage_address,
            class_hash,
            constructor_selector.as_ref(),
            true,
        ),
        _ => {
            vec![error.to_string()]
        }
    };

    finalize_error_stack(&error_stack)
}

/// Generate error stack from top-level entry point execution error.
fn gen_error_trace_from_entry_point_error(
    error: &EntryPointExecutionError,
    storage_address: &ContractAddress,
    class_hash: &ClassHash,
    entry_point_selector: Option<&EntryPointSelector>,
    is_ctor: bool,
) -> ErrorStack {
    let mut error_stack: ErrorStack = ErrorStack::new();
    let depth = 0;
    let preamble = if is_ctor {
        ctor_preamble(depth, storage_address, class_hash, entry_point_selector)
    } else {
        frame_preamble(
            depth,
            "Error in the called contract",
            storage_address,
            class_hash,
            entry_point_selector,
        )
    };
    error_stack.push(preamble);
    extract_entry_point_execution_error_into_stack_trace(&mut error_stack, depth + 1, error);
    error_stack
}

fn extract_cairo_run_error_into_stack_trace(
    error_stack: &mut Vec<String>,
    depth: usize,
    error: &CairoRunError,
) {
    if let CairoRunError::VmException(vm_exception) = error {
        return extract_vm_exception_into_stack_trace(error_stack, depth, vm_exception);
    }
    error_stack.push(error.to_string());
}

fn extract_vm_exception_into_stack_trace(
    error_stack: &mut Vec<String>,
    depth: usize,
    vm_exception: &VmException,
) {
    let vm_exception_preamble = format!("Error at pc=0:{}:", vm_exception.pc);
    error_stack.push(vm_exception_preamble);

    if let Some(traceback) = &vm_exception.traceback {
        error_stack.push(traceback.to_string());
    }
    extract_virtual_machine_error_into_stack_trace(error_stack, depth, &vm_exception.inner_exc)
}

fn extract_virtual_machine_error_into_stack_trace(
    error_stack: &mut Vec<String>,
    depth: usize,
    vm_error: &VirtualMachineError,
) {
    match vm_error {
        VirtualMachineError::Hint(ref boxed_hint_error) => {
            if let HintError::Internal(internal_vm_error) = &boxed_hint_error.1 {
                return extract_virtual_machine_error_into_stack_trace(
                    error_stack,
                    depth,
                    internal_vm_error,
                );
            }
            error_stack.push(boxed_hint_error.1.to_string());
        }
        VirtualMachineError::Other(anyhow_error) => {
            let syscall_exec_err = anyhow_error.downcast_ref::<SyscallExecutionError>();
            if let Some(downcast_anyhow) = syscall_exec_err {
                extract_syscall_execution_error_into_stack_trace(
                    error_stack,
                    depth,
                    downcast_anyhow,
                )
            } else {
                let deprecated_syscall_exec_err =
                    anyhow_error.downcast_ref::<DeprecatedSyscallExecutionError>();
                if let Some(downcast_anyhow) = deprecated_syscall_exec_err {
                    extract_deprecated_syscall_execution_error_into_stack_trace(
                        error_stack,
                        depth,
                        downcast_anyhow,
                    )
                }
            }
        }
        _ => {
            error_stack.push(format!("{}\n", vm_error));
        }
    }
}

fn frame_preamble(
    depth: usize,
    preamble_text: &str,
    storage_address: &ContractAddress,
    class_hash: &ClassHash,
    selector: Option<&EntryPointSelector>,
) -> String {
    format!(
        "{}: {} (contract address: {}, class hash: {}, selector: {}):",
        depth,
        preamble_text,
        storage_address.0.key(),
        class_hash,
        if let Some(selector) = selector {
            format!("{}", selector.0)
        } else {
            "UNKNOWN".to_string()
        }
    )
}

fn ctor_preamble(
    depth: usize,
    storage_address: &ContractAddress,
    class_hash: &ClassHash,
    selector: Option<&EntryPointSelector>,
) -> String {
    frame_preamble(
        depth,
        "Error in the contract class constructor",
        storage_address,
        class_hash,
        selector,
    )
}

fn call_contract_preamble(
    depth: usize,
    storage_address: &ContractAddress,
    class_hash: &ClassHash,
    selector: &EntryPointSelector,
) -> String {
    frame_preamble(
        depth,
        "Error in the called contract",
        storage_address,
        class_hash,
        Some(selector),
    )
}

fn library_call_preamble(
    depth: usize,
    storage_address: &ContractAddress,
    class_hash: &ClassHash,
    selector: &EntryPointSelector,
) -> String {
    frame_preamble(depth, "Error in a library call", storage_address, class_hash, Some(selector))
}

fn extract_syscall_execution_error_into_stack_trace(
    error_stack: &mut Vec<String>,
    depth: usize,
    syscall_error: &SyscallExecutionError,
) {
    match syscall_error {
        SyscallExecutionError::CallContractExecutionError {
            class_hash,
            storage_address,
            selector,
            error,
        } => {
            error_stack.push(call_contract_preamble(depth, storage_address, class_hash, selector));
            extract_syscall_execution_error_into_stack_trace(error_stack, depth + 1, error)
        }
        SyscallExecutionError::LibraryCallExecutionError {
            class_hash,
            storage_address,
            selector,
            error,
        } => {
            error_stack.push(library_call_preamble(depth, storage_address, class_hash, selector));
            extract_syscall_execution_error_into_stack_trace(error_stack, depth + 1, error);
        }
        SyscallExecutionError::ConstructorEntryPointExecutionError(
            ConstructorEntryPointExecutionError::ExecutionError {
                error: entry_point_error,
                class_hash,
                contract_address,
                constructor_selector,
            },
        ) => {
            error_stack.push(ctor_preamble(
                depth,
                contract_address,
                class_hash,
                constructor_selector.as_ref(),
            ));
            extract_entry_point_execution_error_into_stack_trace(
                error_stack,
                depth,
                entry_point_error,
            )
        }
        SyscallExecutionError::EntryPointExecutionError(entry_point_error) => {
            extract_entry_point_execution_error_into_stack_trace(
                error_stack,
                depth,
                entry_point_error,
            )
        }
        _ => {
            error_stack.push(syscall_error.to_string());
        }
    }
}

fn extract_deprecated_syscall_execution_error_into_stack_trace(
    error_stack: &mut Vec<String>,
    depth: usize,
    syscall_error: &DeprecatedSyscallExecutionError,
) {
    match syscall_error {
        DeprecatedSyscallExecutionError::CallContractExecutionError {
            class_hash,
            storage_address,
            selector,
            error,
        } => {
            error_stack.push(call_contract_preamble(depth, storage_address, class_hash, selector));
            extract_deprecated_syscall_execution_error_into_stack_trace(
                error_stack,
                depth + 1,
                error,
            )
        }
        DeprecatedSyscallExecutionError::LibraryCallExecutionError {
            class_hash,
            storage_address,
            selector,
            error,
        } => {
            error_stack.push(library_call_preamble(depth, storage_address, class_hash, selector));
            extract_deprecated_syscall_execution_error_into_stack_trace(
                error_stack,
                depth + 1,
                error,
            )
        }
        DeprecatedSyscallExecutionError::ConstructorEntryPointExecutionError(
            ConstructorEntryPointExecutionError::ExecutionError {
                error: entry_point_error,
                class_hash,
                contract_address,
                constructor_selector,
            },
        ) => {
            error_stack.push(ctor_preamble(
                depth,
                contract_address,
                class_hash,
                constructor_selector.as_ref(),
            ));
            extract_entry_point_execution_error_into_stack_trace(
                error_stack,
                depth,
                entry_point_error,
            )
        }
        DeprecatedSyscallExecutionError::EntryPointExecutionError(entry_point_error) => {
            extract_entry_point_execution_error_into_stack_trace(
                error_stack,
                depth,
                entry_point_error,
            )
        }
        _ => error_stack.push(syscall_error.to_string()),
    }
}

fn extract_entry_point_execution_error_into_stack_trace(
    error_stack: &mut Vec<String>,
    depth: usize,
    entry_point_error: &EntryPointExecutionError,
) {
    match entry_point_error {
        EntryPointExecutionError::CairoRunError(cairo_run_error) => {
            extract_cairo_run_error_into_stack_trace(error_stack, depth, cairo_run_error)
        }
        _ => error_stack.push(format!("{}\n", entry_point_error)),
    }
}
