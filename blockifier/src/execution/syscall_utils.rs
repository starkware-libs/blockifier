use std::collections::HashMap;
use std::rc::Rc;

use anyhow::Result;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};
use cairo_rs::hint_processor::builtin_hint_processor::hint_utils::get_ptr_from_var_name;
use cairo_rs::hint_processor::hint_processor_definition::HintReference;
use cairo_rs::serde::deserialize_program::ApTracking;
use cairo_rs::types::exec_scope::ExecutionScopes;
use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;

use crate::execution::cairo_run_utils::get_felt_from_memory_cell;
use crate::execution::syscall_structs::get_syscall_info;

/// Responsible for managing the state of StarkNet syscalls.
pub struct SyscallHandler {
    pub expected_syscall_ptr: Relocatable,
}

impl SyscallHandler {
    pub fn new(initial_syscall_ptr: Relocatable) -> Self {
        SyscallHandler { expected_syscall_ptr: initial_syscall_ptr }
    }
}

pub fn execute_syscall(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    let syscall_handler = exec_scopes.get_mut_ref::<SyscallHandler>("syscall_handler")?;
    let syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;
    // TODO(AlonH, 21/12/2022): Return error instead of panic.
    assert_eq!(&syscall_ptr, &syscall_handler.expected_syscall_ptr);

    let selector = get_felt_from_memory_cell(vm.get_maybe(&syscall_ptr)?)?;
    let syscall_infos = get_syscall_info();
    let syscall_info = syscall_infos
        .get(&selector)
        // TODO(AlonH, 21/12/2022): Return error instead of panic.
        .unwrap_or_else(|| panic!("{:?} is not a valid selector.", selector));
    let request = (syscall_info.syscall_request_factory)(vm, &syscall_ptr)?;

    let response = request.execute()?;
    response.write_response(vm, &(&syscall_ptr + syscall_info.syscall_request_size))?;

    syscall_handler.expected_syscall_ptr = &syscall_handler.expected_syscall_ptr
        + syscall_info.syscall_request_size
        + syscall_info.syscall_response_size;

    Ok(())
}

pub fn add_syscall_hints(
    hint_processor: &mut BuiltinHintProcessor,
    _syscall_handler: &mut SyscallHandler,
) {
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
        execute_syscall_hint,
    );
}
