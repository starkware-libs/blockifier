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
use starknet_api::transaction::{Calldata, EventContent, MessageToL1};

use crate::execution::common_hints::{add_common_hints, HintExecutionResult};
use crate::execution::entry_point::{CallEntryPoint, CallInfo, Retdata};
use crate::execution::errors::SyscallExecutionError;
use crate::execution::execution_utils::{
    felt_to_bigint, get_felt_from_memory_cell, get_felt_range,
};
use crate::execution::hint_code;
use crate::execution::syscalls::{SyscallRequest, SyscallResult};
use crate::state::state_api::State;

/// Executes StarkNet syscalls (stateful protocol hints) during the execution of an EP call.
pub struct SyscallHintProcessor<'a, S: State> {
    // Input for execution.
    pub state: &'a mut S,
    pub storage_address: ContractAddress,
    builtin_hint_processor: BuiltinHintProcessor,

    // Execution results.
    /// Inner calls invoked by the current execution.
    pub inner_calls: Vec<CallInfo>,
    pub events: Vec<EventContent>,
    pub l2_to_l1_messages: Vec<MessageToL1>,

    // Kept for validations during the run.
    expected_syscall_ptr: Relocatable,
}

impl<'a, S: State> SyscallHintProcessor<'a, S> {
    pub fn new(
        initial_syscall_ptr: Relocatable,
        state: &'a mut S,
        storage_address: ContractAddress,
    ) -> Self {
        let mut builtin_hint_processor = BuiltinHintProcessor::new_empty();
        add_common_hints(&mut builtin_hint_processor);

        SyscallHintProcessor {
            state,
            storage_address,
            builtin_hint_processor,
            inner_calls: vec![],
            events: vec![],
            l2_to_l1_messages: vec![],
            expected_syscall_ptr: initial_syscall_ptr,
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
    ) -> HintExecutionResult {
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

impl<S: State> HintProcessor for SyscallHintProcessor<'_, S> {
    fn execute_hint(
        &mut self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        constants: &HashMap<String, BigInt>,
    ) -> HintExecutionResult {
        let hint = hint_data
            .downcast_ref::<HintProcessorData>()
            .ok_or(VirtualMachineError::WrongHintData)?;
        if hint_code::SYSCALL_HINTS.contains(&&*hint.code) {
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
    state: &'a mut impl State,
    call_entry_point: &CallEntryPoint,
) -> (Relocatable, SyscallHintProcessor<'a, impl State>) {
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
    retdata: Retdata,
) -> SyscallResult<()> {
    let retdata_size = felt_to_bigint(StarkFelt::from(retdata.0.len() as u64));
    vm.insert_value(ptr, retdata_size)?;

    // Write response payload to the memory.
    let segment = vm.add_memory_segment();
    vm.insert_value(&(ptr + 1), segment)?;
    let data: Vec<MaybeRelocatable> = retdata.0.iter().map(|x| felt_to_bigint(*x).into()).collect();
    vm.load_data(&segment.into(), data)?;

    Ok(())
}

pub fn read_felt_array(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<Vec<StarkFelt>> {
    let array_size = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
    let Some(array_data_ptr) = vm.get_maybe(&(ptr + 1))? else {
        return Err(VirtualMachineError::NoneInMemoryRange.into())
    };

    Ok(get_felt_range(vm, &array_data_ptr, array_size.try_into()?)?)
}

pub fn read_calldata(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<Calldata> {
    Ok(Calldata(read_felt_array(vm, ptr)?.into()))
}

pub fn read_call_params(
    vm: &VirtualMachine,
    ptr: &Relocatable,
) -> SyscallResult<(EntryPointSelector, Calldata)> {
    let function_selector = EntryPointSelector(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?);
    let calldata = read_calldata(vm, &(ptr + 1))?;

    Ok((function_selector, calldata))
}

pub fn execute_inner_call(
    call_entry_point: CallEntryPoint,
    syscall_handler: &mut SyscallHintProcessor<'_, impl State>,
) -> SyscallResult<Retdata> {
    let call_info = call_entry_point.execute(syscall_handler.state)?;
    let retdata = call_info.execution.retdata.clone();
    syscall_handler.inner_calls.push(call_info);

    Ok(retdata)
}
