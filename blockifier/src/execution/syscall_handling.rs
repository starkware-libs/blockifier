use std::collections::HashMap;
use std::rc::Rc;

use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};
use cairo_rs::hint_processor::builtin_hint_processor::hint_utils::get_ptr_from_var_name;
use cairo_rs::hint_processor::hint_processor_definition::HintReference;
use cairo_rs::serde::deserialize_program::ApTracking;
use cairo_rs::types::exec_scope::ExecutionScopes;
use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::runners::cairo_runner::CairoRunner;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use starknet_api::core::ContractAddress;

use crate::cached_state::{CachedState, DictStateReader};
use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::execution::errors::SyscallExecutionError;
use crate::execution::execution_utils::get_felt_from_memory_cell;
use crate::execution::syscall_structs::{SyscallRequest, SyscallResult};

#[cfg(test)]
#[path = "syscall_handling_test.rs"]
mod test;

/// Executes StarkNet syscalls (stateful protocol hints) during the execution of an EP call.
pub struct SyscallHandler {
    expected_syscall_ptr: Relocatable,
    pub state: CachedState<DictStateReader>,
    pub storage_address: ContractAddress,
    /// Inner calls invoked by the current execution.
    pub inner_calls: Vec<CallInfo>,
}

impl SyscallHandler {
    pub fn new(
        initial_syscall_ptr: Relocatable,
        state: CachedState<DictStateReader>,
        // TODO(AlonH, 21/12/2022): Consider referencing outer_call when lifetimes make it possible
        // (LambdaClass).
        storage_address: ContractAddress,
    ) -> Self {
        SyscallHandler {
            expected_syscall_ptr: initial_syscall_ptr,
            state,
            inner_calls: vec![],
            storage_address,
        }
    }

    pub fn verify_syscall_ptr(&self, actual_ptr: &Relocatable) -> SyscallResult<()> {
        if actual_ptr != &self.expected_syscall_ptr {
            return Err(SyscallExecutionError::BadSyscallPointer {
                expected_ptr: self.expected_syscall_ptr.clone(),
                actual_ptr: actual_ptr.clone(),
            });
        }
        Ok(())
    }
}

/// Infers and executes the next syscall.
/// Must comply with the API of a hint function, as defined by the `HintProcessor`.
pub fn execute_syscall(
    vm: &mut VirtualMachine,
    execution_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    let syscall_handler = execution_scopes.get_mut_ref::<SyscallHandler>("syscall_handler")?;
    let mut syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;
    syscall_handler.verify_syscall_ptr(&syscall_ptr)?;

    let selector = get_felt_from_memory_cell(vm.get_maybe(&syscall_ptr)?)?;
    let selector_size = 1;
    syscall_ptr = &syscall_ptr + selector_size;

    let request = SyscallRequest::read(selector, vm, &syscall_ptr)?;
    syscall_ptr = &syscall_ptr + request.size();

    let response = request.execute(syscall_handler)?;
    let response_size = response.size();
    response.write(vm, &syscall_ptr)?;
    syscall_handler.expected_syscall_ptr = &syscall_ptr + response_size;

    Ok(())
}

pub fn add_syscall_hints(hint_processor: &mut BuiltinHintProcessor) {
    let execute_syscall_hint = Rc::new(HintFunc(Box::new(execute_syscall)));
    hint_processor.add_hint(
        String::from(
            "syscall_handler.storage_read(segments=segments, syscall_ptr=ids.syscall_ptr)",
        ),
        execute_syscall_hint.clone(),
    );
    hint_processor.add_hint(
        String::from(
            "syscall_handler.storage_write(segments=segments, syscall_ptr=ids.syscall_ptr)",
        ),
        execute_syscall_hint.clone(),
    );
    hint_processor.add_hint(
        String::from(
            "syscall_handler.library_call(segments=segments, syscall_ptr=ids.syscall_ptr)",
        ),
        execute_syscall_hint.clone(),
    );
    hint_processor.add_hint(
        String::from(
            "syscall_handler.call_contract(segments=segments, syscall_ptr=ids.syscall_ptr)",
        ),
        execute_syscall_hint,
    );
}

pub fn initialize_syscall_handler(
    cairo_runner: &mut CairoRunner,
    vm: &mut VirtualMachine,
    state: &mut CachedState<DictStateReader>,
    call_entry_point: &CallEntryPoint,
) -> (Relocatable, BuiltinHintProcessor) {
    let syscall_segment = vm.add_memory_segment();
    let mut hint_processor = BuiltinHintProcessor::new_empty();
    // TODO(AlonH, 21/12/2022): Remove clone (also Clone attribute and mut. refs.) when `state`
    // becomes a reference.
    let syscall_handler = SyscallHandler::new(
        syscall_segment.clone(),
        state.clone(),
        call_entry_point.storage_address,
    );
    add_syscall_hints(&mut hint_processor);
    cairo_runner
        .exec_scopes
        .assign_or_update_variable("syscall_handler", Box::new(syscall_handler));
    (syscall_segment, hint_processor)
}
