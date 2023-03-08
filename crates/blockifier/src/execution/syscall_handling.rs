use std::any::Any;
use std::collections::{HashMap, HashSet};

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
use starknet_api::state::StorageKey;
use starknet_api::transaction::Calldata;

use crate::execution::common_hints::{extended_builtin_hint_processor, HintExecutionResult};
use crate::execution::entry_point::{
    CallEntryPoint, CallInfo, ExecutionContext, OrderedEvent, OrderedL2ToL1Message,
};
use crate::execution::errors::SyscallExecutionError;
use crate::execution::execution_utils::{
    felt_from_memory_ptr, felt_range_from_ptr, stark_felt_to_felt, ReadOnlySegment,
    ReadOnlySegments,
};
use crate::execution::hint_code;
use crate::execution::syscalls::{
    call_contract, delegate_call, delegate_l1_handler, deploy, emit_event, get_block_number,
    get_block_timestamp, get_caller_address, get_contract_address, get_sequencer_address,
    get_tx_info, get_tx_signature, library_call, library_call_l1_handler, send_message_to_l1,
    storage_read, storage_write, StorageReadResponse, StorageWriteResponse, SyscallRequest,
    SyscallResponse, SyscallResult, SyscallSelector,
};
use crate::state::state_api::State;

/// Executes StarkNet syscalls (stateful protocol hints) during the execution of an entry point
/// call.
pub struct SyscallHintProcessor<'a, 'b, S: State> {
    // Input for execution.
    pub context: &'b mut ExecutionContext<'a, S>,
    pub storage_address: ContractAddress,
    pub caller_address: ContractAddress,

    // Execution results.
    /// Inner calls invoked by the current execution.
    pub inner_calls: Vec<CallInfo>,
    pub events: Vec<OrderedEvent>,
    pub l2_to_l1_messages: Vec<OrderedL2ToL1Message>,

    // Fields needed for execution and validation.
    pub read_only_segments: ReadOnlySegments,
    pub syscall_ptr: Relocatable,

    // Additional information gathered during execution.
    pub read_values: Vec<StarkFelt>,
    pub accessed_keys: HashSet<StorageKey>,
    // Used for tracking events order during the current execution.
    pub n_emitted_events: usize,
    // Used for tracking L2-to-L1 messages order during the current execution.
    pub n_sent_messages_to_l1: usize,

    // Additional fields.
    // Invariant: must only contain allowed hints.
    builtin_hint_processor: BuiltinHintProcessor,
    // Transaction info. and signature segments; allocated on-demand.
    tx_signature_start_ptr: Option<Relocatable>,
    tx_info_start_ptr: Option<Relocatable>,
    syscall_counter: HashMap<SyscallSelector, usize>,
}

impl<'a, 'b, S: State> SyscallHintProcessor<'a, 'b, S> {
    pub fn new(
        context: &'b mut ExecutionContext<'a, S>,
        initial_syscall_ptr: Relocatable,
        storage_address: ContractAddress,
        caller_address: ContractAddress,
    ) -> Self {
        SyscallHintProcessor {
            context,
            storage_address,
            caller_address,
            inner_calls: vec![],
            events: vec![],
            l2_to_l1_messages: vec![],
            read_only_segments: ReadOnlySegments::default(),
            syscall_ptr: initial_syscall_ptr,
            read_values: vec![],
            accessed_keys: HashSet::new(),
            n_emitted_events: 0,
            n_sent_messages_to_l1: 0,
            builtin_hint_processor: extended_builtin_hint_processor(),
            tx_signature_start_ptr: None,
            tx_info_start_ptr: None,
            syscall_counter: HashMap::default(),
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

        let selector = SyscallSelector::try_from(self.read_next_syscall_selector(vm)?)?;
        self.increment_syscall_count(&selector);

        match selector {
            SyscallSelector::CallContract => self.execute_syscall(vm, call_contract),
            SyscallSelector::DelegateCall => self.execute_syscall(vm, delegate_call),
            SyscallSelector::DelegateL1Handler => self.execute_syscall(vm, delegate_l1_handler),
            SyscallSelector::Deploy => self.execute_syscall(vm, deploy),
            SyscallSelector::EmitEvent => self.execute_syscall(vm, emit_event),
            SyscallSelector::GetBlockNumber => self.execute_syscall(vm, get_block_number),
            SyscallSelector::GetBlockTimestamp => self.execute_syscall(vm, get_block_timestamp),
            SyscallSelector::GetCallerAddress => self.execute_syscall(vm, get_caller_address),
            SyscallSelector::GetContractAddress => self.execute_syscall(vm, get_contract_address),
            SyscallSelector::GetSequencerAddress => self.execute_syscall(vm, get_sequencer_address),
            SyscallSelector::GetTxInfo => self.execute_syscall(vm, get_tx_info),
            SyscallSelector::GetTxSignature => self.execute_syscall(vm, get_tx_signature),
            SyscallSelector::LibraryCall => self.execute_syscall(vm, library_call),
            SyscallSelector::LibraryCallL1Handler => {
                self.execute_syscall(vm, library_call_l1_handler)
            }
            SyscallSelector::SendMessageToL1 => self.execute_syscall(vm, send_message_to_l1),
            SyscallSelector::StorageRead => self.execute_syscall(vm, storage_read),
            SyscallSelector::StorageWrite => self.execute_syscall(vm, storage_write),
        }
    }

    pub fn get_or_allocate_tx_signature_segment(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> SyscallResult<Relocatable> {
        match self.tx_signature_start_ptr {
            Some(tx_signature_start_ptr) => Ok(tx_signature_start_ptr),
            None => {
                let tx_signature_start_ptr = self.allocate_tx_signature_segment(vm)?;
                self.tx_signature_start_ptr = Some(tx_signature_start_ptr);
                Ok(tx_signature_start_ptr)
            }
        }
    }

    pub fn get_or_allocate_tx_info_start_ptr(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> SyscallResult<Relocatable> {
        match self.tx_info_start_ptr {
            Some(tx_info_start_ptr) => Ok(tx_info_start_ptr),
            None => {
                let tx_info_start_ptr = self.allocate_tx_info_segment(vm)?;
                self.tx_info_start_ptr = Some(tx_info_start_ptr);
                Ok(tx_info_start_ptr)
            }
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
        ExecuteCallback: FnOnce(
            Request,
            &mut VirtualMachine,
            &mut SyscallHintProcessor<'_, '_, S>,
        ) -> SyscallResult<Response>,
    {
        let request = Request::read(vm, self.syscall_ptr)?;
        self.syscall_ptr += Request::SIZE;

        let response = execute_callback(request, vm, self)?;
        response.write(vm, self.syscall_ptr)?;
        self.syscall_ptr += Response::SIZE;

        Ok(())
    }

    fn read_next_syscall_selector(&mut self, vm: &mut VirtualMachine) -> SyscallResult<StarkFelt> {
        let selector = felt_from_memory_ptr(vm, self.syscall_ptr)?;
        self.syscall_ptr = self.syscall_ptr + 1;

        Ok(selector)
    }

    fn increment_syscall_count(&mut self, selector: &SyscallSelector) {
        let syscall_count = self.syscall_counter.entry(*selector).or_default();
        *syscall_count += 1;
    }

    fn allocate_tx_signature_segment(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> SyscallResult<Relocatable> {
        let signature = &self.context.account_tx_context.signature.0;
        let signature =
            signature.iter().map(|&x| MaybeRelocatable::from(stark_felt_to_felt(x))).collect();
        let signature_segment_start_ptr = self.read_only_segments.allocate(vm, &signature)?;

        Ok(signature_segment_start_ptr)
    }

    fn allocate_tx_info_segment(&mut self, vm: &mut VirtualMachine) -> SyscallResult<Relocatable> {
        let tx_signature_start_ptr = self.get_or_allocate_tx_signature_segment(vm)?;
        let account_tx_context = self.context.account_tx_context;
        let tx_signature_length = account_tx_context.signature.0.len();
        let tx_info: Vec<MaybeRelocatable> = vec![
            stark_felt_to_felt(account_tx_context.version.0).into(),
            stark_felt_to_felt(*account_tx_context.sender_address.0.key()).into(),
            Felt::from(account_tx_context.max_fee.0).into(),
            tx_signature_length.into(),
            tx_signature_start_ptr.into(),
            stark_felt_to_felt(account_tx_context.transaction_hash.0).into(),
            Felt::from_bytes_be(self.context.block_context.chain_id.0.as_bytes()).into(),
            stark_felt_to_felt(account_tx_context.nonce.0).into(),
        ];

        let tx_info_start_ptr = self.read_only_segments.allocate(vm, &tx_info)?;
        Ok(tx_info_start_ptr)
    }

    pub fn get_contract_storage_at(
        &mut self,
        key: StorageKey,
    ) -> SyscallResult<StorageReadResponse> {
        self.accessed_keys.insert(key);
        let value = self.context.state.get_storage_at(self.storage_address, key)?;
        self.read_values.push(value);

        Ok(StorageReadResponse { value })
    }

    pub fn set_contract_storage_at(
        &mut self,
        key: StorageKey,
        value: StarkFelt,
    ) -> SyscallResult<StorageWriteResponse> {
        self.accessed_keys.insert(key);
        self.context.state.set_storage_at(self.storage_address, key, value);

        Ok(StorageWriteResponse {})
    }
}

impl<'a, 'b, S: State> HintProcessor for SyscallHintProcessor<'a, 'b, S> {
    fn execute_hint(
        &mut self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        constants: &HashMap<String, Felt>,
    ) -> HintExecutionResult {
        let hint = hint_data.downcast_ref::<HintProcessorData>().ok_or(HintError::WrongHintData)?;
        if hint_code::SYSCALL_HINTS.contains(hint.code.as_str()) {
            return self.execute_next_syscall(vm, &hint.ids_data, &hint.ap_tracking);
        }

        self.builtin_hint_processor.execute_hint(vm, exec_scopes, hint_data, constants)
    }
}

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

pub fn write_felt(vm: &mut VirtualMachine, ptr: Relocatable, felt: StarkFelt) -> SyscallResult<()> {
    Ok(vm.insert_value(ptr, stark_felt_to_felt(felt))?)
}

pub fn read_felt_array(vm: &VirtualMachine, ptr: Relocatable) -> SyscallResult<Vec<StarkFelt>> {
    let array_size = felt_from_memory_ptr(vm, ptr)?;
    let array_data_ptr = vm.get_maybe(&(ptr + 1)).ok_or(VirtualMachineError::NoneInMemoryRange)?;

    Ok(felt_range_from_ptr(vm, &array_data_ptr, usize::try_from(array_size)?)?)
}

pub fn read_calldata(vm: &VirtualMachine, ptr: Relocatable) -> SyscallResult<Calldata> {
    Ok(Calldata(read_felt_array(vm, ptr)?.into()))
}

pub fn read_call_params(
    vm: &VirtualMachine,
    ptr: Relocatable,
) -> SyscallResult<(EntryPointSelector, Calldata)> {
    let function_selector = EntryPointSelector(felt_from_memory_ptr(vm, ptr)?);
    let calldata = read_calldata(vm, ptr + 1)?;

    Ok((function_selector, calldata))
}

pub fn execute_inner_call(
    call: CallEntryPoint,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_, '_, impl State>,
) -> SyscallResult<ReadOnlySegment> {
    let call_info = call.execute(syscall_handler.context)?;
    let retdata = &call_info.execution.retdata.0;
    let retdata: Vec<MaybeRelocatable> =
        retdata.iter().map(|&x| MaybeRelocatable::from(stark_felt_to_felt(x))).collect();
    let retdata_segment_start_ptr = syscall_handler.read_only_segments.allocate(vm, &retdata)?;

    syscall_handler.inner_calls.push(call_info);
    Ok(ReadOnlySegment { start_ptr: retdata_segment_start_ptr, length: retdata.len() })
}
