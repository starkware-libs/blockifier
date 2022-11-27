use std::collections::HashMap;
use std::mem;

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
use starknet_api::StarkFelt;

use crate::execution::cairo_run_utils::{felt_to_bigint, get_felt_from_memory_cell};
use crate::execution::syscall_structs::{StorageRead, StorageReadRequest, StorageReadResponse};

/// Responsible for managing the state of StarkNet syscalls.
pub struct SyscallHandler {
    pub expected_syscall_ptr: Relocatable,
}

impl SyscallHandler {
    pub fn new(initial_syscall_ptr: Relocatable) -> Self {
        SyscallHandler { expected_syscall_ptr: initial_syscall_ptr }
    }
}

pub fn storage_read(
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
    let address = get_felt_from_memory_cell(vm.get_maybe(&(&syscall_ptr + 1))?)?;
    let _request = StorageReadRequest { selector, address };

    // TODO(AlonH, 21/12/2022): Perform state read.
    let value = StarkFelt::from_u64(17);
    let response = StorageReadResponse { value };
    vm.insert_value(
        &(&syscall_ptr + mem::size_of::<StorageReadRequest>() / mem::size_of::<BigInt>()),
        felt_to_bigint(response.value),
    )?;

    let syscall_size = mem::size_of::<StorageRead>() / mem::size_of::<BigInt>();
    syscall_handler.expected_syscall_ptr = &syscall_handler.expected_syscall_ptr + syscall_size;

    Ok(())
}

pub fn add_syscall_hints(
    hint_processor: &mut BuiltinHintProcessor,
    _syscall_handler: &mut SyscallHandler,
) {
    let storage_read_hint = HintFunc(Box::new(storage_read));
    hint_processor.add_hint(
        String::from(
            "syscall_handler.storage_read(segments=segments, syscall_ptr=ids.syscall_ptr)",
        ),
        storage_read_hint,
    );
}
