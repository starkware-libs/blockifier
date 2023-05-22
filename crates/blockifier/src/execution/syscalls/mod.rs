use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::vm_core::VirtualMachine;
use starknet_api::core::{
    calculate_contract_address, ClassHash, ContractAddress, EntryPointSelector,
};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, EthAddress, EventContent, EventData, EventKey, L2ToL1Payload,
};

use self::hint_processor::{
    create_retdata_segment, execute_inner_call, execute_library_call, felt_to_bool,
    read_call_params, read_calldata, read_felt_array, write_segment, SyscallExecutionError,
    SyscallHintProcessor,
};
use crate::execution::deprecated_syscalls::DeprecatedSyscallSelector;
use crate::execution::entry_point::{
    CallEntryPoint, CallType, MessageToL1, OrderedEvent, OrderedL2ToL1Message,
};
use crate::execution::execution_utils::{
    execute_deployment, felt_from_ptr, stark_felt_to_felt, write_felt, write_maybe_relocatable,
    ReadOnlySegment,
};

pub mod hint_processor;

#[cfg(test)]
#[path = "syscalls_test.rs"]
pub mod syscalls_test;

pub type SyscallResult<T> = Result<T, SyscallExecutionError>;
pub type WriteResponseResult = SyscallResult<()>;

type SyscallSelector = DeprecatedSyscallSelector;

pub trait SyscallRequest: Sized {
    fn read(_vm: &VirtualMachine, _ptr: &mut Relocatable) -> SyscallResult<Self>;
}

pub trait SyscallResponse {
    fn write(self, _vm: &mut VirtualMachine, _ptr: &mut Relocatable) -> WriteResponseResult;
}

// Syscall header structs.
pub struct SyscallRequestWrapper<T: SyscallRequest> {
    pub gas_counter: StarkFelt,
    pub request: T,
}
impl<T: SyscallRequest> SyscallRequest for SyscallRequestWrapper<T> {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self> {
        let gas_counter = felt_from_ptr(vm, ptr)?;
        let request = T::read(vm, ptr)?;
        Ok(Self { gas_counter, request })
    }
}

pub enum SyscallResponseWrapper<T: SyscallResponse> {
    Success { gas_counter: StarkFelt, response: T },
    Failure { gas_counter: StarkFelt, error_data: Vec<StarkFelt> },
}
impl<T: SyscallResponse> SyscallResponse for SyscallResponseWrapper<T> {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        match self {
            Self::Success { gas_counter, response } => {
                write_felt(vm, ptr, gas_counter)?;
                // 0 to indicate success.
                write_felt(vm, ptr, StarkFelt::from(0_u8))?;
                response.write(vm, ptr)
            }
            Self::Failure { gas_counter, error_data } => {
                write_felt(vm, ptr, gas_counter)?;
                // 1 to indicate failure.
                write_felt(vm, ptr, StarkFelt::from(1_u8))?;

                // Write the error data to a new memory segment.
                let revert_reason_start = vm.add_memory_segment();
                let revert_reason_end = vm.load_data(
                    revert_reason_start,
                    &error_data.into_iter().map(stark_felt_to_felt).map(Into::into).collect(),
                )?;

                // Write the start and end pointers of the error data.
                write_maybe_relocatable(vm, ptr, revert_reason_start)?;
                write_maybe_relocatable(vm, ptr, revert_reason_end)?;
                Ok(())
            }
        }
    }
}

// Common structs.

#[derive(Debug, Eq, PartialEq)]
pub struct EmptyRequest;

impl SyscallRequest for EmptyRequest {
    fn read(_vm: &VirtualMachine, _ptr: &mut Relocatable) -> SyscallResult<EmptyRequest> {
        Ok(EmptyRequest)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct EmptyResponse;

impl SyscallResponse for EmptyResponse {
    fn write(self, _vm: &mut VirtualMachine, _ptr: &mut Relocatable) -> WriteResponseResult {
        Ok(())
    }
}

#[derive(Debug)]
pub struct SingleSegmentResponse {
    segment: ReadOnlySegment,
}

impl SyscallResponse for SingleSegmentResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_segment(vm, ptr, self.segment)
    }
}

// CallContract syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct CallContractRequest {
    pub contract_address: ContractAddress,
    pub function_selector: EntryPointSelector,
    pub calldata: Calldata,
}

impl SyscallRequest for CallContractRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<CallContractRequest> {
        let contract_address = ContractAddress::try_from(felt_from_ptr(vm, ptr)?)?;
        let (function_selector, calldata) = read_call_params(vm, ptr)?;

        Ok(CallContractRequest { contract_address, function_selector, calldata })
    }
}

pub type CallContractResponse = SingleSegmentResponse;

pub fn call_contract(
    request: CallContractRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<CallContractResponse> {
    let storage_address = request.contract_address;
    let entry_point = CallEntryPoint {
        class_hash: None,
        code_address: Some(storage_address),
        entry_point_type: EntryPointType::External,
        entry_point_selector: request.function_selector,
        calldata: request.calldata,
        storage_address,
        caller_address: syscall_handler.storage_address(),
        call_type: CallType::Call,
    };
    let retdata_segment = execute_inner_call(entry_point, vm, syscall_handler)?;

    Ok(CallContractResponse { segment: retdata_segment })
}

// Deploy syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct DeployRequest {
    pub class_hash: ClassHash,
    pub contract_address_salt: ContractAddressSalt,
    pub constructor_calldata: Calldata,
    pub deploy_from_zero: bool,
}

impl SyscallRequest for DeployRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<DeployRequest> {
        let class_hash = ClassHash(felt_from_ptr(vm, ptr)?);
        let contract_address_salt = ContractAddressSalt(felt_from_ptr(vm, ptr)?);
        let constructor_calldata = read_calldata(vm, ptr)?;
        let deploy_from_zero = felt_from_ptr(vm, ptr)?;

        Ok(DeployRequest {
            class_hash,
            contract_address_salt,
            constructor_calldata,
            deploy_from_zero: felt_to_bool(deploy_from_zero)?,
        })
    }
}

#[derive(Debug)]
pub struct DeployResponse {
    pub contract_address: ContractAddress,
    pub constructor_retdata: ReadOnlySegment,
}

impl SyscallResponse for DeployResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_felt(vm, ptr, *self.contract_address.0.key())?;
        write_segment(vm, ptr, self.constructor_retdata)
    }
}

pub fn deploy(
    request: DeployRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<DeployResponse> {
    let deployer_address = syscall_handler.storage_address();
    let deployer_address_for_calculation = match request.deploy_from_zero {
        true => ContractAddress::default(),
        false => deployer_address,
    };
    let deployed_contract_address = calculate_contract_address(
        request.contract_address_salt,
        request.class_hash,
        &request.constructor_calldata,
        deployer_address_for_calculation,
    )?;

    let is_deploy_account_tx = false;
    let call_info = execute_deployment(
        syscall_handler.state,
        syscall_handler.context,
        request.class_hash,
        deployed_contract_address,
        deployer_address,
        request.constructor_calldata,
        is_deploy_account_tx,
    )?;

    let constructor_retdata =
        create_retdata_segment(vm, syscall_handler, &call_info.execution.retdata.0)?;

    syscall_handler.inner_calls.push(call_info);

    Ok(DeployResponse { contract_address: deployed_contract_address, constructor_retdata })
}

// EmitEvent syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct EmitEventRequest {
    pub content: EventContent,
}

impl SyscallRequest for EmitEventRequest {
    // The Cairo struct contains: `keys_len`, `keys`, `data_len`, `data`·
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<EmitEventRequest> {
        let keys =
            read_felt_array::<SyscallExecutionError>(vm, ptr)?.into_iter().map(EventKey).collect();
        let data = EventData(read_felt_array::<SyscallExecutionError>(vm, ptr)?);

        Ok(EmitEventRequest { content: EventContent { keys, data } })
    }
}

type EmitEventResponse = EmptyResponse;

pub fn emit_event(
    request: EmitEventRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<EmitEventResponse> {
    let mut execution_context = &mut syscall_handler.context;
    let ordered_event =
        OrderedEvent { order: execution_context.n_emitted_events, event: request.content };
    syscall_handler.events.push(ordered_event);
    execution_context.n_emitted_events += 1;

    Ok(EmitEventResponse {})
}

// GetExecutionInfo syscall.

type GetExecutionInfoRequest = EmptyRequest;

#[derive(Debug, Eq, PartialEq)]
pub struct GetExecutionInfoResponse {
    pub execution_info_ptr: Relocatable,
}

impl SyscallResponse for GetExecutionInfoResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_maybe_relocatable(vm, ptr, self.execution_info_ptr)?;
        Ok(())
    }
}
pub fn get_execution_info(
    _request: GetExecutionInfoRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<GetExecutionInfoResponse> {
    let execution_info_ptr = syscall_handler.get_or_allocate_execution_info_segment(vm)?;

    Ok(GetExecutionInfoResponse { execution_info_ptr })
}

// LibraryCall syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct LibraryCallRequest {
    pub class_hash: ClassHash,
    pub function_selector: EntryPointSelector,
    pub calldata: Calldata,
}

impl SyscallRequest for LibraryCallRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<LibraryCallRequest> {
        let class_hash = ClassHash(felt_from_ptr(vm, ptr)?);
        let (function_selector, calldata) = read_call_params(vm, ptr)?;

        Ok(LibraryCallRequest { class_hash, function_selector, calldata })
    }
}

type LibraryCallResponse = CallContractResponse;

pub fn library_call(
    request: LibraryCallRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<LibraryCallResponse> {
    let call_to_external = true;
    let retdata_segment = execute_library_call(
        syscall_handler,
        vm,
        request.class_hash,
        None,
        call_to_external,
        request.function_selector,
        request.calldata,
    )?;

    Ok(LibraryCallResponse { segment: retdata_segment })
}

// LibraryCallL1Handler syscall.

pub fn library_call_l1_handler(
    request: LibraryCallRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<LibraryCallResponse> {
    let call_to_external = false;
    let retdata_segment = execute_library_call(
        syscall_handler,
        vm,
        request.class_hash,
        None,
        call_to_external,
        request.function_selector,
        request.calldata,
    )?;

    Ok(LibraryCallResponse { segment: retdata_segment })
}

// ReplaceClass syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct ReplaceClassRequest {
    pub class_hash: ClassHash,
}

impl SyscallRequest for ReplaceClassRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<ReplaceClassRequest> {
        let class_hash = ClassHash(felt_from_ptr(vm, ptr)?);

        Ok(ReplaceClassRequest { class_hash })
    }
}

pub type ReplaceClassResponse = EmptyResponse;

pub fn replace_class(
    request: ReplaceClassRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<ReplaceClassResponse> {
    // Ensure the class is declared (by reading it).
    syscall_handler.state.get_compiled_contract_class(&request.class_hash)?;
    syscall_handler
        .state
        .set_class_hash_at(syscall_handler.storage_address(), request.class_hash)?;

    Ok(ReplaceClassResponse {})
}

// SendMessageToL1 syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct SendMessageToL1Request {
    pub message: MessageToL1,
}

impl SyscallRequest for SendMessageToL1Request {
    // The Cairo struct contains: `to_address`, `payload_size`, `payload`.
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<SendMessageToL1Request> {
        let to_address = EthAddress::try_from(felt_from_ptr(vm, ptr)?)?;
        let payload = L2ToL1Payload(read_felt_array::<SyscallExecutionError>(vm, ptr)?);

        Ok(SendMessageToL1Request { message: MessageToL1 { to_address, payload } })
    }
}

type SendMessageToL1Response = EmptyResponse;

pub fn send_message_to_l1(
    request: SendMessageToL1Request,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<SendMessageToL1Response> {
    let mut execution_context = &mut syscall_handler.context;
    let ordered_message_to_l1 = OrderedL2ToL1Message {
        order: execution_context.n_sent_messages_to_l1,
        message: request.message,
    };
    syscall_handler.l2_to_l1_messages.push(ordered_message_to_l1);
    execution_context.n_sent_messages_to_l1 += 1;

    Ok(SendMessageToL1Response {})
}

// TODO(spapini): Do something with address domain in read and write.
// StorageRead syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct StorageReadRequest {
    pub address_domain: StarkFelt,
    pub address: StorageKey,
}

impl SyscallRequest for StorageReadRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<StorageReadRequest> {
        let address_domain = felt_from_ptr(vm, ptr)?;
        if address_domain != StarkFelt::from(0_u8) {
            return Err(SyscallExecutionError::InvalidAddressDomain { address_domain });
        }
        let address = StorageKey::try_from(felt_from_ptr(vm, ptr)?)?;
        Ok(StorageReadRequest { address_domain, address })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct StorageReadResponse {
    pub value: StarkFelt,
}

impl SyscallResponse for StorageReadResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_felt(vm, ptr, self.value)?;
        Ok(())
    }
}

pub fn storage_read(
    request: StorageReadRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<StorageReadResponse> {
    syscall_handler.get_contract_storage_at(request.address)
}

// StorageWrite syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct StorageWriteRequest {
    pub address_domain: StarkFelt,
    pub address: StorageKey,
    pub value: StarkFelt,
}

impl SyscallRequest for StorageWriteRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<StorageWriteRequest> {
        let address_domain = felt_from_ptr(vm, ptr)?;
        if address_domain != StarkFelt::from(0_u8) {
            return Err(SyscallExecutionError::InvalidAddressDomain { address_domain });
        }
        let address = StorageKey::try_from(felt_from_ptr(vm, ptr)?)?;
        let value = felt_from_ptr(vm, ptr)?;
        Ok(StorageWriteRequest { address_domain, address, value })
    }
}

pub type StorageWriteResponse = EmptyResponse;

pub fn storage_write(
    request: StorageWriteRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<StorageWriteResponse> {
    // Read the value before the write operation in order to log it in the list of read·
    // values. This is needed to correctly build the `DictAccess` entry corresponding to·
    // `storage_write` syscall in the OS.
    syscall_handler.get_contract_storage_at(request.address)?;
    syscall_handler.set_contract_storage_at(request.address, request.value)
}
