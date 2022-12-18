use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::vm_core::VirtualMachine;
use starknet_api::core::EntryPointSelector;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::CallData;

use crate::execution::entry_point::CallEntryPoint;
use crate::execution::errors::SyscallExecutionError;
use crate::execution::execution_utils::{
    felt_to_bigint, get_felt_from_memory_cell, get_felt_range,
};
use crate::execution::syscall_handling::SyscallHandler;
use crate::execution::syscalls::SyscallResult;

// TODO(Noa, 26/12/2022): Consider implementing it as a From trait.
pub fn felt_to_bool(felt: StarkFelt) -> SyscallResult<bool> {
    if felt == StarkFelt::from(0) {
        Ok(false)
    } else if felt == StarkFelt::from(1) {
        Ok(true)
    } else {
        Err(SyscallExecutionError::InvalidSyscallInput {
            input: felt,
            info: String::from(
                "The deploy_from_zero field in the deploy system call must be 0 or 1.",
            ),
        })
    }
}

pub fn write_retdata(
    vm: &mut VirtualMachine,
    ptr: &Relocatable,
    retdata: Vec<StarkFelt>,
) -> SyscallResult<()> {
    let retdata_size = felt_to_bigint(StarkFelt::from(retdata.len() as u64));
    vm.insert_value(ptr, retdata_size)?;

    // Write response payload to the memory.
    let segment = vm.add_memory_segment();
    vm.insert_value(&(ptr + 1), &segment)?;
    let data: Vec<MaybeRelocatable> =
        retdata.into_iter().map(|x| felt_to_bigint(x).into()).collect();
    vm.load_data(&segment.into(), data)?;

    Ok(())
}

pub fn read_calldata(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<CallData> {
    let calldata_size = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
    let calldata_ptr = match vm.get_maybe(&(ptr + 1))? {
        Some(ptr) => ptr,
        None => return Err(VirtualMachineError::NoneInMemoryRange.into()),
    };
    let calldata = CallData(get_felt_range(vm, &calldata_ptr, calldata_size.try_into()?)?);

    Ok(calldata)
}

pub fn read_call_params(
    vm: &VirtualMachine,
    ptr: &Relocatable,
) -> SyscallResult<(EntryPointSelector, CallData)> {
    let function_selector = EntryPointSelector(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?);
    let calldata = read_calldata(vm, &(ptr + 1))?;

    Ok((function_selector, calldata))
}

pub fn execute_inner_call(
    call_entry_point: CallEntryPoint,
    syscall_handler: &mut SyscallHandler,
) -> SyscallResult<Vec<StarkFelt>> {
    let call_info = call_entry_point.execute(&mut syscall_handler.state)?;
    let retdata = call_info.execution.retdata.clone();
    syscall_handler.inner_calls.push(call_info);

    Ok(retdata)
}
