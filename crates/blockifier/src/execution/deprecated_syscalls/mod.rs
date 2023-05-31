use cairo_felt::Felt252;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::vm_core::VirtualMachine;
use serde::Deserialize;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{
    calculate_contract_address, ClassHash, ContractAddress, EntryPointSelector,
};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, EthAddress, EventContent, EventData, EventKey, L2ToL1Payload,
};
use strum_macros::EnumIter;

use self::hint_processor::{
    execute_inner_call, execute_library_call, felt_to_bool, read_call_params, read_calldata,
    read_felt_array, DeprecatedSyscallExecutionError, DeprecatedSyscallHintProcessor,
};
use crate::execution::entry_point::{
    CallEntryPoint, CallType, MessageToL1, OrderedEvent, OrderedL2ToL1Message,
};
use crate::execution::execution_utils::{
    execute_deployment, stark_felt_from_ptr, write_maybe_relocatable, write_stark_felt,
    ReadOnlySegment,
};

#[cfg(test)]
#[path = "deprecated_syscalls_test.rs"]
pub mod deprecated_syscalls_test;
pub mod hint_processor;

pub type DeprecatedSyscallResult<T> = Result<T, DeprecatedSyscallExecutionError>;
pub type WriteResponseResult = DeprecatedSyscallResult<()>;

#[derive(Clone, Copy, Debug, Deserialize, EnumIter, Eq, Hash, PartialEq)]
pub enum DeprecatedSyscallSelector {
    CallContract,
    DelegateCall,
    DelegateL1Handler,
    Deploy,
    EmitEvent,
    GetBlockNumber,
    GetBlockTimestamp,
    GetCallerAddress,
    GetContractAddress,
    GetExecutionInfo,
    GetSequencerAddress,
    GetTxInfo,
    GetTxSignature,
    LibraryCall,
    LibraryCallL1Handler,
    ReplaceClass,
    SendMessageToL1,
    StorageRead,
    StorageWrite,
}

impl TryFrom<StarkFelt> for DeprecatedSyscallSelector {
    type Error = DeprecatedSyscallExecutionError;
    fn try_from(raw_selector: StarkFelt) -> Result<Self, Self::Error> {
        // Remove leading zero bytes from selector.
        let selector_bytes = raw_selector.bytes();
        let first_non_zero = selector_bytes.iter().position(|&byte| byte != b'\0').unwrap_or(32);

        match &selector_bytes[first_non_zero..] {
            b"CallContract" => Ok(Self::CallContract),
            b"DelegateCall" => Ok(Self::DelegateCall),
            b"DelegateL1Handler" => Ok(Self::DelegateL1Handler),
            b"Deploy" => Ok(Self::Deploy),
            b"EmitEvent" => Ok(Self::EmitEvent),
            b"GetBlockNumber" => Ok(Self::GetBlockNumber),
            b"GetBlockTimestamp" => Ok(Self::GetBlockTimestamp),
            b"GetCallerAddress" => Ok(Self::GetCallerAddress),
            b"GetContractAddress" => Ok(Self::GetContractAddress),
            b"GetExecutionInfo" => Ok(Self::GetExecutionInfo),
            b"GetSequencerAddress" => Ok(Self::GetSequencerAddress),
            b"GetTxInfo" => Ok(Self::GetTxInfo),
            b"GetTxSignature" => Ok(Self::GetTxSignature),
            b"LibraryCall" => Ok(Self::LibraryCall),
            b"LibraryCallL1Handler" => Ok(Self::LibraryCallL1Handler),
            b"ReplaceClass" => Ok(Self::ReplaceClass),
            b"SendMessageToL1" => Ok(Self::SendMessageToL1),
            b"StorageRead" => Ok(Self::StorageRead),
            b"StorageWrite" => Ok(Self::StorageWrite),
            _ => {
                Err(DeprecatedSyscallExecutionError::InvalidDeprecatedSyscallSelector(raw_selector))
            }
        }
    }
}

pub trait SyscallRequest: Sized {
    fn read(_vm: &VirtualMachine, _ptr: &mut Relocatable) -> DeprecatedSyscallResult<Self>;
}

pub trait SyscallResponse {
    fn write(self, _vm: &mut VirtualMachine, _ptr: &mut Relocatable) -> WriteResponseResult;
}

// Common structs.

#[derive(Debug, Eq, PartialEq)]
pub struct EmptyRequest;

impl SyscallRequest for EmptyRequest {
    fn read(_vm: &VirtualMachine, _ptr: &mut Relocatable) -> DeprecatedSyscallResult<EmptyRequest> {
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
        write_maybe_relocatable(vm, ptr, self.segment.length)?;
        write_maybe_relocatable(vm, ptr, self.segment.start_ptr)?;
        Ok(())
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
    fn read(
        vm: &VirtualMachine,
        ptr: &mut Relocatable,
    ) -> DeprecatedSyscallResult<CallContractRequest> {
        let contract_address = ContractAddress::try_from(stark_felt_from_ptr(vm, ptr)?)?;
        let (function_selector, calldata) = read_call_params(vm, ptr)?;

        Ok(CallContractRequest { contract_address, function_selector, calldata })
    }
}

pub type CallContractResponse = SingleSegmentResponse;

pub fn call_contract(
    request: CallContractRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<CallContractResponse> {
    let storage_address = request.contract_address;
    let entry_point = CallEntryPoint {
        class_hash: None,
        code_address: Some(storage_address),
        entry_point_type: EntryPointType::External,
        entry_point_selector: request.function_selector,
        calldata: request.calldata,
        storage_address,
        caller_address: syscall_handler.storage_address,
        call_type: CallType::Call,
    };
    let retdata_segment = execute_inner_call(entry_point, vm, syscall_handler)?;

    Ok(CallContractResponse { segment: retdata_segment })
}

// DelegateCall syscall.

type DelegateCallRequest = CallContractRequest;
type DelegateCallResponse = CallContractResponse;

pub fn delegate_call(
    request: DelegateCallRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<DelegateCallResponse> {
    let call_to_external = true;
    let storage_address = request.contract_address;
    let class_hash = syscall_handler.state.get_class_hash_at(storage_address)?;
    let retdata_segment = execute_library_call(
        syscall_handler,
        vm,
        class_hash,
        Some(storage_address),
        call_to_external,
        request.function_selector,
        request.calldata,
    )?;

    Ok(DelegateCallResponse { segment: retdata_segment })
}

// DelegateCallL1Handler syscall.

pub fn delegate_l1_handler(
    request: DelegateCallRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<DelegateCallResponse> {
    let call_to_external = false;
    let storage_address = request.contract_address;
    let class_hash = syscall_handler.state.get_class_hash_at(storage_address)?;
    let retdata_segment = execute_library_call(
        syscall_handler,
        vm,
        class_hash,
        Some(storage_address),
        call_to_external,
        request.function_selector,
        request.calldata,
    )?;

    Ok(DelegateCallResponse { segment: retdata_segment })
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
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> DeprecatedSyscallResult<DeployRequest> {
        let class_hash = ClassHash(stark_felt_from_ptr(vm, ptr)?);
        let contract_address_salt = ContractAddressSalt(stark_felt_from_ptr(vm, ptr)?);
        let constructor_calldata = read_calldata(vm, ptr)?;
        let deploy_from_zero = stark_felt_from_ptr(vm, ptr)?;

        Ok(DeployRequest {
            class_hash,
            contract_address_salt,
            constructor_calldata,
            deploy_from_zero: felt_to_bool(deploy_from_zero)?,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct DeployResponse {
    pub contract_address: ContractAddress,
}

impl SyscallResponse for DeployResponse {
    // The Cairo struct contains: `contract_address`, `constructor_retdata_size`,
    // `constructor_retdata`.
    // Nonempty constructor retdata is currently not supported.
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_stark_felt(vm, ptr, *self.contract_address.0.key())?;
        write_maybe_relocatable(vm, ptr, 0)?;
        write_maybe_relocatable(vm, ptr, 0)?;
        Ok(())
    }
}

pub fn deploy(
    request: DeployRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<DeployResponse> {
    let deployer_address = syscall_handler.storage_address;
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
    syscall_handler.inner_calls.push(call_info);

    Ok(DeployResponse { contract_address: deployed_contract_address })
}

// EmitEvent syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct EmitEventRequest {
    pub content: EventContent,
}

impl SyscallRequest for EmitEventRequest {
    // The Cairo struct contains: `keys_len`, `keys`, `data_len`, `data`·
    fn read(
        vm: &VirtualMachine,
        ptr: &mut Relocatable,
    ) -> DeprecatedSyscallResult<EmitEventRequest> {
        let keys = read_felt_array::<DeprecatedSyscallExecutionError>(vm, ptr)?
            .into_iter()
            .map(EventKey)
            .collect();
        let data = EventData(read_felt_array::<DeprecatedSyscallExecutionError>(vm, ptr)?);

        Ok(EmitEventRequest { content: EventContent { keys, data } })
    }
}

type EmitEventResponse = EmptyResponse;

pub fn emit_event(
    request: EmitEventRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<EmitEventResponse> {
    let execution_context = &mut syscall_handler.context;
    let ordered_event =
        OrderedEvent { order: execution_context.n_emitted_events, event: request.content };
    syscall_handler.events.push(ordered_event);
    execution_context.n_emitted_events += 1;

    Ok(EmitEventResponse {})
}

// GetBlockNumber syscall.

type GetBlockNumberRequest = EmptyRequest;

#[derive(Debug, Eq, PartialEq)]
pub struct GetBlockNumberResponse {
    pub block_number: BlockNumber,
}

impl SyscallResponse for GetBlockNumberResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_maybe_relocatable(vm, ptr, Felt252::from(self.block_number.0))?;
        Ok(())
    }
}

pub fn get_block_number(
    _request: GetBlockNumberRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<GetBlockNumberResponse> {
    Ok(GetBlockNumberResponse { block_number: syscall_handler.context.block_context.block_number })
}

// GetBlockTimestamp syscall.

type GetBlockTimestampRequest = EmptyRequest;

#[derive(Debug, Eq, PartialEq)]
pub struct GetBlockTimestampResponse {
    pub block_timestamp: BlockTimestamp,
}

impl SyscallResponse for GetBlockTimestampResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_maybe_relocatable(vm, ptr, Felt252::from(self.block_timestamp.0))?;
        Ok(())
    }
}

pub fn get_block_timestamp(
    _request: GetBlockTimestampRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<GetBlockTimestampResponse> {
    Ok(GetBlockTimestampResponse {
        block_timestamp: syscall_handler.context.block_context.block_timestamp,
    })
}

// GetCallerAddress syscall.

type GetCallerAddressRequest = EmptyRequest;
type GetCallerAddressResponse = GetContractAddressResponse;

pub fn get_caller_address(
    _request: GetCallerAddressRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<GetCallerAddressResponse> {
    Ok(GetCallerAddressResponse { address: syscall_handler.caller_address })
}

// GetContractAddress syscall.

type GetContractAddressRequest = EmptyRequest;

#[derive(Debug, Eq, PartialEq)]
pub struct GetContractAddressResponse {
    pub address: ContractAddress,
}

impl SyscallResponse for GetContractAddressResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_stark_felt(vm, ptr, *self.address.0.key())?;
        Ok(())
    }
}

pub fn get_contract_address(
    _request: GetContractAddressRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<GetContractAddressResponse> {
    Ok(GetContractAddressResponse { address: syscall_handler.storage_address })
}

// GetSequencerAddress syscall.

type GetSequencerAddressRequest = EmptyRequest;
type GetSequencerAddressResponse = GetContractAddressResponse;

pub fn get_sequencer_address(
    _request: GetSequencerAddressRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<GetSequencerAddressResponse> {
    Ok(GetSequencerAddressResponse {
        address: syscall_handler.context.block_context.sequencer_address,
    })
}

// GetTxInfo syscall.

type GetTxInfoRequest = EmptyRequest;

#[derive(Debug, Eq, PartialEq)]
pub struct GetTxInfoResponse {
    pub tx_info_start_ptr: Relocatable,
}

impl SyscallResponse for GetTxInfoResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_maybe_relocatable(vm, ptr, self.tx_info_start_ptr)?;
        Ok(())
    }
}
pub fn get_tx_info(
    _request: GetTxInfoRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<GetTxInfoResponse> {
    let tx_info_start_ptr = syscall_handler.get_or_allocate_tx_info_start_ptr(vm)?;

    Ok(GetTxInfoResponse { tx_info_start_ptr })
}

// GetTxSignature syscall.

type GetTxSignatureRequest = EmptyRequest;
type GetTxSignatureResponse = SingleSegmentResponse;

pub fn get_tx_signature(
    _request: GetTxSignatureRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<GetTxSignatureResponse> {
    let start_ptr = syscall_handler.get_or_allocate_tx_signature_segment(vm)?;
    let length = syscall_handler.context.account_tx_context.signature.0.len();

    Ok(GetTxSignatureResponse { segment: ReadOnlySegment { start_ptr, length } })
}

// LibraryCall syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct LibraryCallRequest {
    pub class_hash: ClassHash,
    pub function_selector: EntryPointSelector,
    pub calldata: Calldata,
}

impl SyscallRequest for LibraryCallRequest {
    fn read(
        vm: &VirtualMachine,
        ptr: &mut Relocatable,
    ) -> DeprecatedSyscallResult<LibraryCallRequest> {
        let class_hash = ClassHash(stark_felt_from_ptr(vm, ptr)?);
        let (function_selector, calldata) = read_call_params(vm, ptr)?;

        Ok(LibraryCallRequest { class_hash, function_selector, calldata })
    }
}

type LibraryCallResponse = CallContractResponse;

pub fn library_call(
    request: LibraryCallRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<LibraryCallResponse> {
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
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<LibraryCallResponse> {
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
    fn read(
        vm: &VirtualMachine,
        ptr: &mut Relocatable,
    ) -> DeprecatedSyscallResult<ReplaceClassRequest> {
        let class_hash = ClassHash(stark_felt_from_ptr(vm, ptr)?);

        Ok(ReplaceClassRequest { class_hash })
    }
}

pub type ReplaceClassResponse = EmptyResponse;

pub fn replace_class(
    request: ReplaceClassRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<ReplaceClassResponse> {
    // Ensure the class is declared (by reading it).
    syscall_handler.state.get_compiled_contract_class(&request.class_hash)?;
    syscall_handler.state.set_class_hash_at(syscall_handler.storage_address, request.class_hash)?;

    Ok(ReplaceClassResponse {})
}

// SendMessageToL1 syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct SendMessageToL1Request {
    pub message: MessageToL1,
}

impl SyscallRequest for SendMessageToL1Request {
    // The Cairo struct contains: `to_address`, `payload_size`, `payload`.
    fn read(
        vm: &VirtualMachine,
        ptr: &mut Relocatable,
    ) -> DeprecatedSyscallResult<SendMessageToL1Request> {
        let to_address = EthAddress::try_from(stark_felt_from_ptr(vm, ptr)?)?;
        let payload = L2ToL1Payload(read_felt_array::<DeprecatedSyscallExecutionError>(vm, ptr)?);

        Ok(SendMessageToL1Request { message: MessageToL1 { to_address, payload } })
    }
}

type SendMessageToL1Response = EmptyResponse;

pub fn send_message_to_l1(
    request: SendMessageToL1Request,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<SendMessageToL1Response> {
    let execution_context = &mut syscall_handler.context;
    let ordered_message_to_l1 = OrderedL2ToL1Message {
        order: execution_context.n_sent_messages_to_l1,
        message: request.message,
    };
    syscall_handler.l2_to_l1_messages.push(ordered_message_to_l1);
    execution_context.n_sent_messages_to_l1 += 1;

    Ok(SendMessageToL1Response {})
}

// StorageRead syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct StorageReadRequest {
    pub address: StorageKey,
}

impl SyscallRequest for StorageReadRequest {
    fn read(
        vm: &VirtualMachine,
        ptr: &mut Relocatable,
    ) -> DeprecatedSyscallResult<StorageReadRequest> {
        let address = StorageKey::try_from(stark_felt_from_ptr(vm, ptr)?)?;
        Ok(StorageReadRequest { address })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct StorageReadResponse {
    pub value: StarkFelt,
}

impl SyscallResponse for StorageReadResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_stark_felt(vm, ptr, self.value)?;
        Ok(())
    }
}

pub fn storage_read(
    request: StorageReadRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<StorageReadResponse> {
    syscall_handler.get_contract_storage_at(request.address)
}

// StorageWrite syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct StorageWriteRequest {
    pub address: StorageKey,
    pub value: StarkFelt,
}

impl SyscallRequest for StorageWriteRequest {
    fn read(
        vm: &VirtualMachine,
        ptr: &mut Relocatable,
    ) -> DeprecatedSyscallResult<StorageWriteRequest> {
        let address = StorageKey::try_from(stark_felt_from_ptr(vm, ptr)?)?;
        let value = stark_felt_from_ptr(vm, ptr)?;
        Ok(StorageWriteRequest { address, value })
    }
}

pub type StorageWriteResponse = EmptyResponse;

pub fn storage_write(
    request: StorageWriteRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut DeprecatedSyscallHintProcessor<'_>,
) -> DeprecatedSyscallResult<StorageWriteResponse> {
    // Read the value before the write operation in order to log it in the list of read·
    // values. This is needed to correctly build the `DictAccess` entry corresponding to·
    // `storage_write` syscall in the OS.
    syscall_handler.get_contract_storage_at(request.address)?;
    syscall_handler.set_contract_storage_at(request.address, request.value)
}
