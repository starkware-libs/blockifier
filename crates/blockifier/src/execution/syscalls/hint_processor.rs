use std::any::Any;
use std::collections::{HashMap, HashSet};

use cairo_felt::Felt252;
use cairo_lang_casm::hints::{Hint, StarknetHint};
use cairo_lang_casm::operand::{BinOpOperand, DerefOrImmediate, Operation, Register, ResOperand};
use cairo_lang_runner::casm_run::execute_core_hint_base;
use cairo_vm::hint_processor::hint_processor_definition::{HintProcessor, HintReference};
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::errors::math_errors::MathError;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::vm_core::VirtualMachine;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_api::transaction::Calldata;
use starknet_api::StarknetApiError;
use thiserror::Error;

use crate::execution::common_hints::HintExecutionResult;
use crate::execution::entry_point::{
    CallEntryPoint, CallInfo, CallType, ExecutionContext, OrderedEvent, OrderedL2ToL1Message,
};
use crate::execution::errors::EntryPointExecutionError;
use crate::execution::execution_utils::{
    felt_range_from_ptr, stark_felt_from_ptr, stark_felt_to_felt, write_maybe_relocatable,
    ReadOnlySegment, ReadOnlySegments,
};
use crate::execution::syscalls::{
    call_contract, deploy, emit_event, get_execution_info, library_call, library_call_l1_handler,
    replace_class, send_message_to_l1, storage_read, storage_write, StorageReadResponse,
    StorageWriteResponse, SyscallRequest, SyscallRequestWrapper, SyscallResponse,
    SyscallResponseWrapper, SyscallResult, SyscallSelector,
};
use crate::state::errors::StateError;
use crate::state::state_api::State;

pub type SyscallCounter = HashMap<SyscallSelector, usize>;

#[derive(Debug, Error)]
pub enum SyscallExecutionError {
    #[error("Bad syscall_ptr; expected: {expected_ptr:?}, got: {actual_ptr:?}.")]
    BadSyscallPointer { expected_ptr: Relocatable, actual_ptr: Relocatable },
    #[error(transparent)]
    InnerCallExecutionError(#[from] EntryPointExecutionError),
    #[error("Invalid syscall input: {input:?}; {info}")]
    InvalidSyscallInput { input: StarkFelt, info: String },
    #[error("Invalid syscall selector: {0:?}.")]
    InvalidSyscallSelector(StarkFelt),
    #[error(transparent)]
    MathError(#[from] cairo_vm::types::errors::math_errors::MathError),
    #[error(transparent)]
    MemoryError(#[from] MemoryError),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error(transparent)]
    VirtualMachineError(#[from] VirtualMachineError),
    #[error("Syscall error.")]
    SyscallError { error_data: Vec<StarkFelt> },
    #[error("Invalid address domain: {address_domain}.")]
    InvalidAddressDomain { address_domain: StarkFelt },
}

// Needed for custom hint implementations (in our case, syscall hints) which must comply with the
// cairo-rs API.
impl From<SyscallExecutionError> for HintError {
    fn from(error: SyscallExecutionError) -> Self {
        HintError::CustomHint(error.to_string())
    }
}

/// Executes StarkNet syscalls (stateful protocol hints) during the execution of an entry point
/// call.
pub struct SyscallHintProcessor<'a> {
    // Input for execution.
    pub state: &'a mut dyn State,
    pub context: &'a mut ExecutionContext,
    pub call: CallEntryPoint,

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
    hints: &'a HashMap<String, Hint>,
    // Transaction info. and signature segments; allocated on-demand.
    execution_info_ptr: Option<Relocatable>,
}

impl<'a> SyscallHintProcessor<'a> {
    pub fn new(
        state: &'a mut dyn State,
        context: &'a mut ExecutionContext,
        initial_syscall_ptr: Relocatable,
        call: CallEntryPoint,
        hints: &'a HashMap<String, Hint>,
        read_only_segments: ReadOnlySegments,
    ) -> Self {
        SyscallHintProcessor {
            state,
            context,
            call,
            inner_calls: vec![],
            events: vec![],
            l2_to_l1_messages: vec![],
            read_only_segments,
            syscall_ptr: initial_syscall_ptr,
            read_values: vec![],
            accessed_keys: HashSet::new(),
            hints,
            execution_info_ptr: None,
        }
    }

    pub fn storage_address(&self) -> ContractAddress {
        self.call.storage_address
    }

    pub fn caller_address(&self) -> ContractAddress {
        self.call.caller_address
    }

    pub fn entry_point_selector(&self) -> EntryPointSelector {
        self.call.entry_point_selector
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
        hint: &StarknetHint,
    ) -> HintExecutionResult {
        let StarknetHint::SystemCall{ system: syscall } = hint else {
            return Err(HintError::CustomHint(
                "Test functions are unsupported on starknet.".to_string()
            ));
        };
        let initial_syscall_ptr = get_ptr_from_res_operand_unchecked(vm, syscall);
        self.verify_syscall_ptr(initial_syscall_ptr)?;

        let selector = SyscallSelector::try_from(self.read_next_syscall_selector(vm)?)?;
        self.increment_syscall_count(&selector);

        match selector {
            SyscallSelector::CallContract => self.execute_syscall(vm, call_contract),
            SyscallSelector::Deploy => self.execute_syscall(vm, deploy),
            SyscallSelector::EmitEvent => self.execute_syscall(vm, emit_event),
            SyscallSelector::GetExecutionInfo => self.execute_syscall(vm, get_execution_info),
            SyscallSelector::LibraryCall => self.execute_syscall(vm, library_call),
            SyscallSelector::LibraryCallL1Handler => {
                self.execute_syscall(vm, library_call_l1_handler)
            }
            SyscallSelector::ReplaceClass => self.execute_syscall(vm, replace_class),
            SyscallSelector::SendMessageToL1 => self.execute_syscall(vm, send_message_to_l1),
            SyscallSelector::StorageRead => self.execute_syscall(vm, storage_read),
            SyscallSelector::StorageWrite => self.execute_syscall(vm, storage_write),
            _ => Err(HintError::UnknownHint(format!("Unsupported syscall selector {selector:?}."))),
        }
    }

    pub fn get_or_allocate_execution_info_segment(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> SyscallResult<Relocatable> {
        match self.execution_info_ptr {
            Some(execution_info_ptr) => Ok(execution_info_ptr),
            None => {
                let execution_info_ptr = self.allocate_execution_info_segment(vm)?;
                self.execution_info_ptr = Some(execution_info_ptr);
                Ok(execution_info_ptr)
            }
        }
    }

    fn execute_syscall<Request, Response, ExecuteCallback>(
        &mut self,
        vm: &mut VirtualMachine,
        execute_callback: ExecuteCallback,
    ) -> HintExecutionResult
    where
        Request: SyscallRequest + std::fmt::Debug,
        Response: SyscallResponse + std::fmt::Debug,
        ExecuteCallback: FnOnce(
            Request,
            &mut VirtualMachine,
            &mut SyscallHintProcessor<'_>,
        ) -> SyscallResult<Response>,
    {
        let SyscallRequestWrapper { gas_counter, request } =
            SyscallRequestWrapper::<Request>::read(vm, &mut self.syscall_ptr)?;

        let original_response = execute_callback(request, vm, self);
        let response = match original_response {
            Ok(response) => SyscallResponseWrapper::Success { gas_counter, response },
            Err(SyscallExecutionError::SyscallError { error_data: data }) => {
                SyscallResponseWrapper::Failure { gas_counter, error_data: data }
            }
            Err(error) => return Err(error.into()),
        };

        response.write(vm, &mut self.syscall_ptr)?;

        Ok(())
    }

    fn read_next_syscall_selector(&mut self, vm: &mut VirtualMachine) -> SyscallResult<StarkFelt> {
        let selector = stark_felt_from_ptr(vm, &mut self.syscall_ptr)?;

        Ok(selector)
    }

    fn increment_syscall_count(&mut self, selector: &SyscallSelector) {
        let syscall_count = self.context.resources.syscall_counter.entry(*selector).or_default();
        *syscall_count += 1;
    }

    fn allocate_execution_info_segment(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> SyscallResult<Relocatable> {
        let block_info_ptr = self.allocate_block_info_segment(vm)?;
        let tx_info_ptr = self.allocate_tx_info_segment(vm)?;

        let additional_info: Vec<MaybeRelocatable> = vec![
            block_info_ptr.into(),
            tx_info_ptr.into(),
            stark_felt_to_felt(*self.caller_address().0.key()).into(),
            stark_felt_to_felt(*self.storage_address().0.key()).into(),
            stark_felt_to_felt(self.entry_point_selector().0).into(),
        ];
        let execution_info_segment_start_ptr =
            self.read_only_segments.allocate(vm, &additional_info)?;

        Ok(execution_info_segment_start_ptr)
    }

    fn allocate_block_info_segment(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> SyscallResult<Relocatable> {
        let block_context = &self.context.block_context;
        let block_info: Vec<MaybeRelocatable> = vec![
            Felt252::from(block_context.block_number.0).into(),
            Felt252::from(block_context.block_timestamp.0).into(),
            stark_felt_to_felt(*block_context.sequencer_address.0.key()).into(),
        ];
        let block_info_segment_start_ptr = self.read_only_segments.allocate(vm, &block_info)?;

        Ok(block_info_segment_start_ptr)
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
        let tx_signature_start_ptr = self.allocate_tx_signature_segment(vm)?;
        let account_tx_context = &self.context.account_tx_context;
        let tx_signature_length = account_tx_context.signature.0.len();
        let tx_info: Vec<MaybeRelocatable> = vec![
            stark_felt_to_felt(account_tx_context.version.0).into(),
            stark_felt_to_felt(*account_tx_context.sender_address.0.key()).into(),
            Felt252::from(account_tx_context.max_fee.0).into(),
            tx_signature_length.into(),
            tx_signature_start_ptr.into(),
            stark_felt_to_felt(account_tx_context.transaction_hash.0).into(),
            Felt252::from_bytes_be(self.context.block_context.chain_id.0.as_bytes()).into(),
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
        let value = self.state.get_storage_at(self.storage_address(), key)?;
        self.read_values.push(value);

        Ok(StorageReadResponse { value })
    }

    pub fn set_contract_storage_at(
        &mut self,
        key: StorageKey,
        value: StarkFelt,
    ) -> SyscallResult<StorageWriteResponse> {
        self.accessed_keys.insert(key);
        self.state.set_storage_at(self.storage_address(), key, value);

        Ok(StorageWriteResponse {})
    }
}

/// Retrieves a [Relocatable] from the VM given a [ResOperand].
/// A [ResOperand] represents a CASM result expression, and is deserialized with the hint.
fn get_ptr_from_res_operand_unchecked(vm: &mut VirtualMachine, res: &ResOperand) -> Relocatable {
    let (cell, base_offset) = match res {
        ResOperand::Deref(cell) => (cell, Felt252::from(0)),
        ResOperand::BinOp(BinOpOperand {
            op: Operation::Add,
            a,
            b: DerefOrImmediate::Immediate(b),
        }) => (a, Felt252::from(b.clone().value)),
        _ => panic!("Illegal argument for a buffer."),
    };
    let base = match cell.register {
        Register::AP => vm.get_ap(),
        Register::FP => vm.get_fp(),
    };
    let cell_reloc = (base + (cell.offset as i32)).unwrap();
    (vm.get_relocatable(cell_reloc).unwrap() + &base_offset).unwrap()
}

impl HintProcessor for SyscallHintProcessor<'_> {
    fn execute_hint(
        &mut self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        _constants: &HashMap<String, Felt252>,
    ) -> HintExecutionResult {
        let hint = hint_data.downcast_ref::<Hint>().ok_or(HintError::WrongHintData)?;
        match hint {
            Hint::Core(hint) => execute_core_hint_base(vm, exec_scopes, hint),
            Hint::Starknet(hint) => self.execute_next_syscall(vm, hint),
        }
    }

    /// Trait function to store hint in the hint processor by string.
    fn compile_hint(
        &self,
        hint_code: &str,
        _ap_tracking_data: &ApTracking,
        _reference_ids: &HashMap<String, usize>,
        _references: &HashMap<usize, HintReference>,
    ) -> Result<Box<dyn Any>, VirtualMachineError> {
        Ok(Box::new(self.hints[hint_code].clone()))
    }
}

pub fn felt_to_bool(felt: StarkFelt) -> SyscallResult<bool> {
    if felt == StarkFelt::from(0_u8) {
        Ok(false)
    } else if felt == StarkFelt::from(1_u8) {
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

pub fn read_calldata(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Calldata> {
    Ok(Calldata(read_felt_array::<SyscallExecutionError>(vm, ptr)?.into()))
}

pub fn read_call_params(
    vm: &VirtualMachine,
    ptr: &mut Relocatable,
) -> SyscallResult<(EntryPointSelector, Calldata)> {
    let function_selector = EntryPointSelector(stark_felt_from_ptr(vm, ptr)?);
    let calldata = read_calldata(vm, ptr)?;

    Ok((function_selector, calldata))
}

pub fn execute_inner_call(
    call: CallEntryPoint,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<ReadOnlySegment> {
    let call_info = call.execute(syscall_handler.state, syscall_handler.context)?;
    let raw_retdata = &call_info.execution.retdata.0;

    if call_info.execution.failed {
        // TODO(spapini): Append an error word according to starknet spec if needed.
        // Something like "EXECUTION_ERROR".
        return Err(SyscallExecutionError::SyscallError { error_data: raw_retdata.clone() });
    }

    let retdata_segment = create_retdata_segment(vm, syscall_handler, raw_retdata)?;

    syscall_handler.inner_calls.push(call_info);

    Ok(retdata_segment)
}

pub fn create_retdata_segment(
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    raw_retdata: &[StarkFelt],
) -> SyscallResult<ReadOnlySegment> {
    let retdata: Vec<MaybeRelocatable> =
        raw_retdata.iter().map(|&x| MaybeRelocatable::from(stark_felt_to_felt(x))).collect();
    let retdata_segment_start_ptr = syscall_handler.read_only_segments.allocate(vm, &retdata)?;

    Ok(ReadOnlySegment { start_ptr: retdata_segment_start_ptr, length: retdata.len() })
}

pub fn execute_library_call(
    syscall_handler: &mut SyscallHintProcessor<'_>,
    vm: &mut VirtualMachine,
    class_hash: ClassHash,
    code_address: Option<ContractAddress>,
    call_to_external: bool,
    entry_point_selector: EntryPointSelector,
    calldata: Calldata,
) -> SyscallResult<ReadOnlySegment> {
    let entry_point_type =
        if call_to_external { EntryPointType::External } else { EntryPointType::L1Handler };
    let entry_point = CallEntryPoint {
        class_hash: Some(class_hash),
        code_address,
        entry_point_type,
        entry_point_selector,
        calldata,
        // The call context remains the same in a library call.
        storage_address: syscall_handler.storage_address(),
        caller_address: syscall_handler.caller_address(),
        call_type: CallType::Delegate,
    };

    execute_inner_call(entry_point, vm, syscall_handler)
}

pub fn read_felt_array<TErr>(
    vm: &VirtualMachine,
    ptr: &mut Relocatable,
) -> Result<Vec<StarkFelt>, TErr>
where
    TErr: From<StarknetApiError> + From<VirtualMachineError> + From<MemoryError> + From<MathError>,
{
    let array_data_start_ptr = vm.get_relocatable(*ptr)?;
    *ptr += 1;
    let array_data_end_ptr = vm.get_relocatable(*ptr)?;
    *ptr += 1;
    let array_size = (array_data_end_ptr - array_data_start_ptr)?;

    Ok(felt_range_from_ptr(vm, array_data_start_ptr, array_size)?)
}

pub fn write_segment(
    vm: &mut VirtualMachine,
    ptr: &mut Relocatable,
    segment: ReadOnlySegment,
) -> SyscallResult<()> {
    write_maybe_relocatable(vm, ptr, segment.start_ptr)?;
    let segment_end_ptr = (segment.start_ptr + segment.length)?;
    write_maybe_relocatable(vm, ptr, segment_end_ptr)?;

    Ok(())
}
