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
use cairo_rs::vm::errors::hint_errors::HintError;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::vm_core::VirtualMachine;
use felt::Felt;
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, EventContent, MessageToL1};

use crate::block_context::BlockContext;
use crate::execution::common_hints::{add_common_hints, HintExecutionResult};
use crate::execution::entry_point::{CallEntryPoint, CallInfo, Retdata};
use crate::execution::errors::SyscallExecutionError;
use crate::execution::execution_utils::{
    get_felt_from_memory_cell, get_felt_range, stark_felt_to_felt,
};
use crate::execution::hint_code;
use crate::execution::syscalls::{
    call_contract, deploy, emit_event, get_caller_address, get_contract_address, library_call,
    send_message_to_l1, storage_read, storage_write, SyscallRequest, SyscallResponse,
    SyscallResult,
};
use crate::state::state_api::State;
use crate::transaction::objects::AccountTransactionContext;

/// Executes StarkNet syscalls (stateful protocol hints) during the execution of an EP call.
pub struct SyscallHintProcessor<'a> {
    // Input for execution.
    pub state: &'a mut dyn State,
    pub block_context: &'a BlockContext,
    pub account_tx_context: &'a AccountTransactionContext,
    pub storage_address: ContractAddress,
    pub caller_address: ContractAddress,
    builtin_hint_processor: BuiltinHintProcessor,

    // Execution results.
    /// Inner calls invoked by the current execution.
    pub inner_calls: Vec<CallInfo>,
    pub events: Vec<EventContent>,
    pub l2_to_l1_messages: Vec<MessageToL1>,

    // Kept for validations during the run.
    syscall_ptr: Relocatable,
}

impl<'a> SyscallHintProcessor<'a> {
    pub fn new(
        state: &'a mut dyn State,
        block_context: &'a BlockContext,
        account_tx_context: &'a AccountTransactionContext,
        initial_syscall_ptr: Relocatable,
        storage_address: ContractAddress,
        caller_address: ContractAddress,
    ) -> Self {
        let mut builtin_hint_processor = BuiltinHintProcessor::new_empty();
        add_common_hints(&mut builtin_hint_processor);

        SyscallHintProcessor {
            state,
            block_context,
            account_tx_context,
            storage_address,
            caller_address,
            builtin_hint_processor,
            inner_calls: vec![],
            events: vec![],
            l2_to_l1_messages: vec![],
            syscall_ptr: initial_syscall_ptr,
        }
    }

    pub fn verify_syscall_ptr(&self, actual_ptr: Relocatable) -> SyscallResult<()> {
        if actual_ptr != self.syscall_ptr {
            return Err(SyscallExecutionError::BadSyscallPointer {
                expected_ptr: self.syscall_ptr,
                actual_ptr,
            });
        }

        Ok(())
    }

    /// Infers and executes the next syscall.
    /// Must comply with the API of a hint function, as defined by the `HintProcessor`.
    pub fn execute_next_syscall(
        &mut self,
        vm: &mut VirtualMachine,
        ids_data: &HashMap<String, HintReference>,
        ap_tracking: &ApTracking,
    ) -> HintExecutionResult {
        let initial_syscall_ptr = get_ptr_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)?;
        self.verify_syscall_ptr(initial_syscall_ptr)?;

        let selector = self.read_next_syscall_selector(vm)?;
        let selector_bytes = selector.bytes();
        // Remove leading zero bytes from selector.
        let first_non_zero = selector_bytes.iter().position(|&byte| byte != b'\0').unwrap_or(32);
        match &selector_bytes[first_non_zero..32] {
            b"CallContract" => self.execute_syscall(vm, call_contract),
            b"Deploy" => self.execute_syscall(vm, deploy),
            b"EmitEvent" => self.execute_syscall(vm, emit_event),
            b"GetCallerAddress" => self.execute_syscall(vm, get_caller_address),
            b"GetContractAddress" => self.execute_syscall(vm, get_contract_address),
            b"LibraryCall" => self.execute_syscall(vm, library_call),
            b"SendMessageToL1" => self.execute_syscall(vm, send_message_to_l1),
            b"StorageRead" => self.execute_syscall(vm, storage_read),
            b"StorageWrite" => self.execute_syscall(vm, storage_write),
            _ => Err(HintError::from(SyscallExecutionError::InvalidSyscallSelector(selector))),
        }
    }

    pub fn execute_syscall<Request, Response, ExecuteCallback>(
        &mut self,
        vm: &mut VirtualMachine,
        execute_callback: ExecuteCallback,
    ) -> HintExecutionResult
    where
        Request: SyscallRequest,
        Response: SyscallResponse,
        ExecuteCallback: FnOnce(Request, &mut SyscallHintProcessor<'_>) -> SyscallResult<Response>,
    {
        let request = Request::read(vm, &self.syscall_ptr)?;
        self.syscall_ptr = self.syscall_ptr + Request::SIZE;

        let response = execute_callback(request, self)?;
        response.write(vm, &self.syscall_ptr)?;
        self.syscall_ptr = self.syscall_ptr + Response::SIZE;

        Ok(())
    }

    fn read_next_syscall_selector(&mut self, vm: &mut VirtualMachine) -> SyscallResult<StarkFelt> {
        let selector = get_felt_from_memory_cell(
            vm.get_maybe(&self.syscall_ptr).map_err(VirtualMachineError::from)?,
        )?;
        self.syscall_ptr = self.syscall_ptr + 1;

        Ok(selector)
    }
}

impl HintProcessor for SyscallHintProcessor<'_> {
    fn execute_hint(
        &mut self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        constants: &HashMap<String, Felt>,
    ) -> HintExecutionResult {
        let hint = hint_data.downcast_ref::<HintProcessorData>().ok_or(HintError::WrongHintData)?;
        if hint_code::SYSCALL_HINTS.contains(&&*hint.code) {
            return self.execute_next_syscall(vm, &hint.ids_data, &hint.ap_tracking);
        }

        self.builtin_hint_processor.execute_hint(vm, exec_scopes, hint_data, constants)
    }
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
    let retdata_size = stark_felt_to_felt(StarkFelt::from(retdata.0.len() as u64));
    vm.insert_value(ptr, retdata_size)?;

    // Write response payload to the memory.
    // TODO(AlonH, 21/12/2022): Use read only segments.
    let segment = vm.add_memory_segment();
    vm.insert_value(&(ptr + 1), segment)?;
    let data: Vec<MaybeRelocatable> =
        retdata.0.iter().map(|x| stark_felt_to_felt(*x).into()).collect();
    vm.load_data(&segment.into(), &data)?;

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
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<Retdata> {
    let call_info = call_entry_point.execute(
        syscall_handler.state,
        syscall_handler.block_context,
        syscall_handler.account_tx_context,
    )?;
    let retdata = call_info.execution.retdata.clone();
    syscall_handler.inner_calls.push(call_info);

    Ok(retdata)
}
