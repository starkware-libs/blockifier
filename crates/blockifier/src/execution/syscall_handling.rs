use std::any::Any;
use std::collections::HashMap;
use std::rc::Rc;

use cairo_felt::Felt;
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintProcessorData,
};
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::get_ptr_from_var_name;
use cairo_vm::hint_processor::hint_processor_definition::{HintProcessor, HintReference};
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::vm_core::VirtualMachine;
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, EventContent, MessageToL1};

use crate::block_context::BlockContext;
use crate::execution::common_hints::{extended_builtin_hint_processor, HintExecutionResult};
use crate::execution::entry_point::{CallEntryPoint, CallInfo, Retdata};
use crate::execution::errors::SyscallExecutionError;
use crate::execution::execution_utils::{
    felt_from_memory_ptr, felt_range_from_ptr, stark_felt_to_felt, ReadOnlySegments,
};
use crate::execution::hint_code;
use crate::execution::syscalls::{
    call_contract, deploy, emit_event, get_block_number, get_block_timestamp, get_caller_address,
    get_contract_address, get_sequencer_address, get_tx_signature, library_call,
    send_message_to_l1, storage_read, storage_write, SyscallRequest, SyscallResponse,
    SyscallResult,
};
use crate::state::state_api::State;
use crate::transaction::objects::AccountTransactionContext;

/// Executes StarkNet syscalls (stateful protocol hints) during the execution of an entry point
/// call.
pub struct SyscallHintProcessor<'a> {
    // Input for execution.
    pub state: &'a mut dyn State,
    pub block_context: &'a BlockContext,
    pub account_tx_context: &'a AccountTransactionContext,
    pub storage_address: ContractAddress,
    pub caller_address: ContractAddress,
    // Invariant: must only contain allowed hints.
    builtin_hint_processor: BuiltinHintProcessor,

    // Execution results.
    /// Inner calls invoked by the current execution.
    pub inner_calls: Vec<CallInfo>,
    pub events: Vec<EventContent>,
    pub l2_to_l1_messages: Vec<MessageToL1>,

    // Fields needed for execution and validation.
    pub read_only_segments: ReadOnlySegments,
    pub syscall_ptr: Relocatable,
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
        SyscallHintProcessor {
            state,
            block_context,
            account_tx_context,
            storage_address,
            caller_address,
            builtin_hint_processor: extended_builtin_hint_processor(),
            inner_calls: vec![],
            events: vec![],
            l2_to_l1_messages: vec![],
            read_only_segments: ReadOnlySegments::default(),
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
            b"GetBlockNumber" => self.execute_syscall(vm, get_block_number),
            b"GetBlockTimestamp" => self.execute_syscall(vm, get_block_timestamp),
            b"GetCallerAddress" => self.execute_syscall(vm, get_caller_address),
            b"GetContractAddress" => self.execute_syscall(vm, get_contract_address),
            b"GetSequencerAddress" => self.execute_syscall(vm, get_sequencer_address),
            b"GetTxSignature" => self.execute_syscall(vm, get_tx_signature),
            b"LibraryCall" => self.execute_syscall(vm, library_call),
            b"SendMessageToL1" => self.execute_syscall(vm, send_message_to_l1),
            b"StorageRead" => self.execute_syscall(vm, storage_read),
            b"StorageWrite" => self.execute_syscall(vm, storage_write),
            _ => Err(HintError::from(SyscallExecutionError::InvalidSyscallSelector(selector))),
        }
    }

    fn execute_syscall<Request, Response, ExecuteCallback>(
        &mut self,
        vm: &mut VirtualMachine,
        execute_callback: ExecuteCallback,
    ) -> HintExecutionResult
    where
        Request: SyscallRequest,
        Response: SyscallResponse,
        ExecuteCallback: FnOnce(Request, &mut SyscallHintProcessor<'a>) -> SyscallResult<Response>,
    {
        let request = Request::read(vm, &self.syscall_ptr)?;
        self.syscall_ptr = self.syscall_ptr + Request::SIZE;

        let response = execute_callback(request, self)?;
        response.write(vm, &self.syscall_ptr)?;
        self.syscall_ptr = self.syscall_ptr + Response::SIZE;

        Ok(())
    }

    fn read_next_syscall_selector(&mut self, vm: &mut VirtualMachine) -> SyscallResult<StarkFelt> {
        let selector = felt_from_memory_ptr(vm, &self.syscall_ptr)?;
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

pub fn write_felt(
    vm: &mut VirtualMachine,
    ptr: &Relocatable,
    felt: StarkFelt,
) -> SyscallResult<()> {
    Ok(vm.insert_value(ptr, stark_felt_to_felt(&felt))?)
}

pub fn write_felt_array(
    vm: &mut VirtualMachine,
    ptr: &Relocatable,
    data: &[StarkFelt],
) -> SyscallResult<()> {
    let data_size = StarkFelt::from(data.len() as u64);
    write_felt(vm, ptr, data_size)?;

    // Write response payload to the memory.
    let segment_start_ptr = vm.add_memory_segment();
    vm.insert_value(&(ptr + 1), segment_start_ptr)?;
    let data: Vec<MaybeRelocatable> =
        data.iter().map(|x| MaybeRelocatable::from(stark_felt_to_felt(x))).collect();
    vm.load_data(&MaybeRelocatable::from(segment_start_ptr), &data)?;

    Ok(())
}

pub fn read_felt_array(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<Vec<StarkFelt>> {
    let array_size = felt_from_memory_ptr(vm, ptr)?;
    let Some(array_data_ptr) = vm.get_maybe(&(ptr + 1))? else {
        return Err(VirtualMachineError::NoneInMemoryRange.into())
    };

    Ok(felt_range_from_ptr(vm, &array_data_ptr, usize::try_from(array_size)?)?)
}

pub fn read_calldata(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<Calldata> {
    Ok(Calldata(read_felt_array(vm, ptr)?.into()))
}

pub fn read_call_params(
    vm: &VirtualMachine,
    ptr: &Relocatable,
) -> SyscallResult<(EntryPointSelector, Calldata)> {
    let function_selector = EntryPointSelector(felt_from_memory_ptr(vm, ptr)?);
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
    let retdata = Retdata(Rc::clone(&call_info.execution.retdata.0));
    syscall_handler.inner_calls.push(call_info);

    Ok(retdata)
}
