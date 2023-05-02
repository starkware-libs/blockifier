use std::any::Any;
use std::collections::{HashMap, HashSet};

use cairo_vm::felt::Felt252;
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintProcessorData,
};
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::get_ptr_from_var_name;
use cairo_vm::hint_processor::hint_processor_definition::{HintProcessor, HintReference};
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_api::transaction::Calldata;

use crate::block_context::BlockContext;
use crate::execution::common_hints::{extended_builtin_hint_processor, HintExecutionResult};
use crate::execution::deprecated_syscalls::{
    call_contract, delegate_call, delegate_l1_handler, deploy, emit_event, get_block_number,
    get_block_timestamp, get_caller_address, get_contract_address, get_sequencer_address,
    get_tx_info, get_tx_signature, library_call, library_call_l1_handler, replace_class,
    send_message_to_l1, storage_read, storage_write, DeprecatedSyscallResult,
    DeprecatedSyscallSelector, StorageReadResponse, StorageWriteResponse, SyscallRequest,
    SyscallResponse,
};
use crate::execution::entry_point::{
    CallEntryPoint, CallInfo, ExecutionContext, ExecutionResources, OrderedEvent,
    OrderedL2ToL1Message,
};
use crate::execution::errors::DeprecatedSyscallExecutionError;
use crate::execution::execution_utils::{
    felt_from_ptr, felt_range_from_ptr, stark_felt_to_felt, ReadOnlySegment, ReadOnlySegments,
};
use crate::execution::hint_code;
use crate::state::state_api::State;
use crate::transaction::objects::AccountTransactionContext;

pub type SyscallCounter = HashMap<DeprecatedSyscallSelector, usize>;

/// Executes StarkNet syscalls (stateful protocol hints) during the execution of an entry point
/// call.
pub struct DeprecatedSyscallHintProcessor<'a> {
    // Input for execution.
    pub state: &'a mut dyn State,
    pub execution_resources: &'a mut ExecutionResources,
    pub execution_context: &'a mut ExecutionContext,
    pub block_context: &'a BlockContext,
    pub account_tx_context: &'a AccountTransactionContext,
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

    // Additional fields.
    // Invariant: must only contain allowed hints.
    builtin_hint_processor: BuiltinHintProcessor,
    // Transaction info. and signature segments; allocated on-demand.
    tx_signature_start_ptr: Option<Relocatable>,
    tx_info_start_ptr: Option<Relocatable>,
}

impl<'a> DeprecatedSyscallHintProcessor<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: &'a mut dyn State,
        execution_resources: &'a mut ExecutionResources,
        execution_context: &'a mut ExecutionContext,
        block_context: &'a BlockContext,
        account_tx_context: &'a AccountTransactionContext,
        initial_syscall_ptr: Relocatable,
        storage_address: ContractAddress,
        caller_address: ContractAddress,
    ) -> Self {
        DeprecatedSyscallHintProcessor {
            state,
            execution_resources,
            execution_context,
            block_context,
            account_tx_context,
            storage_address,
            caller_address,
            inner_calls: vec![],
            events: vec![],
            l2_to_l1_messages: vec![],
            read_only_segments: ReadOnlySegments::default(),
            syscall_ptr: initial_syscall_ptr,
            read_values: vec![],
            accessed_keys: HashSet::new(),
            builtin_hint_processor: extended_builtin_hint_processor(),
            tx_signature_start_ptr: None,
            tx_info_start_ptr: None,
        }
    }

    pub fn verify_syscall_ptr(&self, actual_ptr: Relocatable) -> DeprecatedSyscallResult<()> {
        if actual_ptr != self.syscall_ptr {
            return Err(DeprecatedSyscallExecutionError::BadSyscallPointer {
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

        let selector = DeprecatedSyscallSelector::try_from(self.read_next_syscall_selector(vm)?)?;
        self.increment_syscall_count(&selector);

        match selector {
            DeprecatedSyscallSelector::CallContract => self.execute_syscall(vm, call_contract),
            DeprecatedSyscallSelector::DelegateCall => self.execute_syscall(vm, delegate_call),
            DeprecatedSyscallSelector::DelegateL1Handler => {
                self.execute_syscall(vm, delegate_l1_handler)
            }
            DeprecatedSyscallSelector::Deploy => self.execute_syscall(vm, deploy),
            DeprecatedSyscallSelector::EmitEvent => self.execute_syscall(vm, emit_event),
            DeprecatedSyscallSelector::GetBlockNumber => self.execute_syscall(vm, get_block_number),
            DeprecatedSyscallSelector::GetBlockTimestamp => {
                self.execute_syscall(vm, get_block_timestamp)
            }
            DeprecatedSyscallSelector::GetCallerAddress => {
                self.execute_syscall(vm, get_caller_address)
            }
            DeprecatedSyscallSelector::GetContractAddress => {
                self.execute_syscall(vm, get_contract_address)
            }
            DeprecatedSyscallSelector::GetSequencerAddress => {
                self.execute_syscall(vm, get_sequencer_address)
            }
            DeprecatedSyscallSelector::GetTxInfo => self.execute_syscall(vm, get_tx_info),
            DeprecatedSyscallSelector::GetTxSignature => self.execute_syscall(vm, get_tx_signature),
            DeprecatedSyscallSelector::LibraryCall => self.execute_syscall(vm, library_call),
            DeprecatedSyscallSelector::LibraryCallL1Handler => {
                self.execute_syscall(vm, library_call_l1_handler)
            }
            DeprecatedSyscallSelector::ReplaceClass => self.execute_syscall(vm, replace_class),
            DeprecatedSyscallSelector::SendMessageToL1 => {
                self.execute_syscall(vm, send_message_to_l1)
            }
            DeprecatedSyscallSelector::StorageRead => self.execute_syscall(vm, storage_read),
            DeprecatedSyscallSelector::StorageWrite => self.execute_syscall(vm, storage_write),
        }
    }

    pub fn get_or_allocate_tx_signature_segment(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> DeprecatedSyscallResult<Relocatable> {
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
    ) -> DeprecatedSyscallResult<Relocatable> {
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
            &mut DeprecatedSyscallHintProcessor<'_>,
        ) -> DeprecatedSyscallResult<Response>,
    {
        let request = Request::read(vm, self.syscall_ptr)?;
        self.syscall_ptr += Request::SIZE;

        let response = execute_callback(request, vm, self)?;
        response.write(vm, self.syscall_ptr)?;
        self.syscall_ptr += Response::SIZE;

        Ok(())
    }

    fn read_next_syscall_selector(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> DeprecatedSyscallResult<StarkFelt> {
        let selector = felt_from_ptr(vm, self.syscall_ptr)?;
        self.syscall_ptr = (self.syscall_ptr + 1)?;

        Ok(selector)
    }

    fn increment_syscall_count(&mut self, selector: &DeprecatedSyscallSelector) {
        let syscall_count = self.execution_resources.syscall_counter.entry(*selector).or_default();
        *syscall_count += 1;
    }

    fn allocate_tx_signature_segment(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> DeprecatedSyscallResult<Relocatable> {
        let signature = &self.account_tx_context.signature.0;
        let signature =
            signature.iter().map(|&x| MaybeRelocatable::from(stark_felt_to_felt(x))).collect();
        let signature_segment_start_ptr = self.read_only_segments.allocate(vm, &signature)?;

        Ok(signature_segment_start_ptr)
    }

    fn allocate_tx_info_segment(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> DeprecatedSyscallResult<Relocatable> {
        let tx_signature_start_ptr = self.get_or_allocate_tx_signature_segment(vm)?;
        let tx_signature_length = self.account_tx_context.signature.0.len();
        let tx_info: Vec<MaybeRelocatable> = vec![
            stark_felt_to_felt(self.account_tx_context.version.0).into(),
            stark_felt_to_felt(*self.account_tx_context.sender_address.0.key()).into(),
            Felt252::from(self.account_tx_context.max_fee.0).into(),
            tx_signature_length.into(),
            tx_signature_start_ptr.into(),
            stark_felt_to_felt(self.account_tx_context.transaction_hash.0).into(),
            Felt252::from_bytes_be(self.block_context.chain_id.0.as_bytes()).into(),
            stark_felt_to_felt(self.account_tx_context.nonce.0).into(),
        ];

        let tx_info_start_ptr = self.read_only_segments.allocate(vm, &tx_info)?;
        Ok(tx_info_start_ptr)
    }

    pub fn get_contract_storage_at(
        &mut self,
        key: StorageKey,
    ) -> DeprecatedSyscallResult<StorageReadResponse> {
        self.accessed_keys.insert(key);
        let value = self.state.get_storage_at(self.storage_address, key)?;
        self.read_values.push(value);

        Ok(StorageReadResponse { value })
    }

    pub fn set_contract_storage_at(
        &mut self,
        key: StorageKey,
        value: StarkFelt,
    ) -> DeprecatedSyscallResult<StorageWriteResponse> {
        self.accessed_keys.insert(key);
        self.state.set_storage_at(self.storage_address, key, value);

        Ok(StorageWriteResponse {})
    }
}

impl HintProcessor for DeprecatedSyscallHintProcessor<'_> {
    fn execute_hint(
        &mut self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        constants: &HashMap<String, Felt252>,
    ) -> HintExecutionResult {
        let hint = hint_data.downcast_ref::<HintProcessorData>().ok_or(HintError::WrongHintData)?;
        if hint_code::SYSCALL_HINTS.contains(hint.code.as_str()) {
            return self.execute_next_syscall(vm, &hint.ids_data, &hint.ap_tracking);
        }

        self.builtin_hint_processor.execute_hint(vm, exec_scopes, hint_data, constants)
    }
}

pub fn felt_to_bool(felt: StarkFelt) -> DeprecatedSyscallResult<bool> {
    if felt == StarkFelt::from(0) {
        Ok(false)
    } else if felt == StarkFelt::from(1) {
        Ok(true)
    } else {
        Err(DeprecatedSyscallExecutionError::InvalidSyscallInput {
            input: felt,
            info: String::from(
                "The deploy_from_zero field in the deploy system call must be 0 or 1.",
            ),
        })
    }
}

pub fn write_felt(
    vm: &mut VirtualMachine,
    ptr: Relocatable,
    felt: StarkFelt,
) -> DeprecatedSyscallResult<()> {
    Ok(vm.insert_value(ptr, stark_felt_to_felt(felt))?)
}

pub fn read_felt_array(
    vm: &VirtualMachine,
    ptr: Relocatable,
) -> DeprecatedSyscallResult<Vec<StarkFelt>> {
    let array_size = felt_from_ptr(vm, ptr)?;
    let array_data_ptr = vm.get_relocatable((ptr + 1)?)?;

    Ok(felt_range_from_ptr(vm, array_data_ptr, usize::try_from(array_size)?)?)
}

pub fn read_calldata(vm: &VirtualMachine, ptr: Relocatable) -> DeprecatedSyscallResult<Calldata> {
    Ok(Calldata(read_felt_array(vm, ptr)?.into()))
}

pub fn read_call_params(
    vm: &VirtualMachine,
    ptr: Relocatable,
) -> DeprecatedSyscallResult<(EntryPointSelector, Calldata)> {
    let function_selector = EntryPointSelector(felt_from_ptr(vm, ptr)?);
    let calldata = read_calldata(vm, (ptr + 1)?)?;

    Ok((function_selector, calldata))
}

pub fn execute_inner_call(
    call: CallEntryPoint,
    vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<ReadOnlySegment> {
    let call_info = call.execute(
        syscall_handler.state,
        syscall_handler.execution_resources,
        syscall_handler.execution_context,
        syscall_handler.block_context,
        syscall_handler.account_tx_context,
    )?;
    let retdata = &call_info.execution.retdata.0;
    let retdata: Vec<MaybeRelocatable> =
        retdata.iter().map(|&x| MaybeRelocatable::from(stark_felt_to_felt(x))).collect();
    let retdata_segment_start_ptr = syscall_handler.read_only_segments.allocate(vm, &retdata)?;

    syscall_handler.inner_calls.push(call_info);
    Ok(ReadOnlySegment { start_ptr: retdata_segment_start_ptr, length: retdata.len() })
}
