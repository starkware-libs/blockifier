use std::any::Any;
use std::collections::HashMap;

use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintProcessorData,
};
use cairo_rs::hint_processor::builtin_hint_processor::hint_utils::get_ptr_from_var_name;
use cairo_rs::hint_processor::hint_processor_definition::{HintProcessor, HintReference};
use cairo_rs::serde::deserialize_program::ApTracking;
use cairo_rs::types::exec_scope::ExecutionScopes;
use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::CallData;

use crate::execution::common_hints::add_common_hints;
use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::execution::errors::SyscallExecutionError;
use crate::execution::execution_utils::{
    felt_to_bigint, get_felt_from_memory_cell, get_felt_range,
};
use crate::execution::hint_code::SYSCALL_HINTS;
use crate::execution::syscalls::{SyscallRequest, SyscallResult};
use crate::state::cached_state::{CachedState, DictStateReader};

/// Executes StarkNet syscalls (stateful protocol hints) during the execution of an EP call.
pub struct SyscallHintProcessor<'a> {
    expected_syscall_ptr: Relocatable,
    pub state: &'a mut CachedState<DictStateReader>,
    pub storage_address: ContractAddress,
    /// Inner calls invoked by the current execution.
    pub inner_calls: Vec<CallInfo>,
    builtin_hint_processor: BuiltinHintProcessor,
}

impl<'a> SyscallHintProcessor<'a> {
    pub fn new(
        initial_syscall_ptr: Relocatable,
        state: &'a mut CachedState<DictStateReader>,
        // TODO(AlonH, 21/12/2022): Consider referencing outer_call when lifetimes make it possible
        // (LambdaClass).
        storage_address: ContractAddress,
    ) -> Self {
        let mut builtin_hint_processor = BuiltinHintProcessor::new_empty();
        add_common_hints(&mut builtin_hint_processor);
        SyscallHintProcessor {
            expected_syscall_ptr: initial_syscall_ptr,
            state,
            inner_calls: vec![],
            storage_address,
            builtin_hint_processor,
        }
    }

    pub fn verify_syscall_ptr(&self, actual_ptr: Relocatable) -> SyscallResult<()> {
        if actual_ptr != self.expected_syscall_ptr {
            return Err(SyscallExecutionError::BadSyscallPointer {
                expected_ptr: self.expected_syscall_ptr,
                actual_ptr,
            });
        }
        Ok(())
    }

    /// Infers and executes the next syscall.
    /// Must comply with the API of a hint function, as defined by the `HintProcessor`.
    pub fn execute_syscall(
        &mut self,
        vm: &mut VirtualMachine,
        ids_data: &HashMap<String, HintReference>,
        ap_tracking: &ApTracking,
    ) -> Result<(), VirtualMachineError> {
        let mut syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;
        self.verify_syscall_ptr(syscall_ptr)?;

        let selector = get_felt_from_memory_cell(vm.get_maybe(&syscall_ptr)?)?;
        let selector_size = 1;
        syscall_ptr = syscall_ptr + selector_size;

        let request = SyscallRequest::read(selector, vm, &syscall_ptr)?;
        syscall_ptr = syscall_ptr + request.size();

        let response = request.execute(self)?;
        let response_size = response.size();
        response.write(vm, &syscall_ptr)?;
        self.expected_syscall_ptr = syscall_ptr + response_size;

        Ok(())
    }
}

impl HintProcessor for SyscallHintProcessor<'_> {
    fn execute_hint(
        &mut self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        constants: &HashMap<String, BigInt>,
    ) -> Result<(), VirtualMachineError> {
        let hint = hint_data
            .downcast_ref::<HintProcessorData>()
            .ok_or(VirtualMachineError::WrongHintData)?;
        if SYSCALL_HINTS.contains(&&*hint.code) {
            return self.execute_syscall(vm, &hint.ids_data, &hint.ap_tracking);
        }

        self.builtin_hint_processor.execute_hint(vm, exec_scopes, hint_data, constants)
    }

    fn compile_hint(
        &self,
        code: &str,
        ap_tracking: &ApTracking,
        reference_ids: &HashMap<String, usize>,
        references: &HashMap<usize, HintReference>,
    ) -> Result<Box<dyn Any>, VirtualMachineError> {
        self.builtin_hint_processor.compile_hint(code, ap_tracking, reference_ids, references)
    }
}

pub fn initialize_syscall_handler<'a>(
    vm: &mut VirtualMachine,
    state: &'a mut CachedState<DictStateReader>,
    call_entry_point: &CallEntryPoint,
) -> (Relocatable, SyscallHintProcessor<'a>) {
    let syscall_segment = vm.add_memory_segment();
    let syscall_handler =
        SyscallHintProcessor::new(syscall_segment, state, call_entry_point.storage_address);

    (syscall_segment, syscall_handler)
}

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
    vm.insert_value(&(ptr + 1), segment)?;
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
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<Vec<StarkFelt>> {
    let call_info = call_entry_point.execute(syscall_handler.state)?;
    let retdata = call_info.execution.retdata.clone();
    syscall_handler.inner_calls.push(call_info);

    Ok(retdata)
}
