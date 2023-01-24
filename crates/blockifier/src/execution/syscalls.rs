use cairo_felt::Felt;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::vm_core::VirtualMachine;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{
    calculate_contract_address, ClassHash, ContractAddress, EntryPointSelector,
};
use starknet_api::hash::StarkFelt;
use starknet_api::state::{EntryPointType, StorageKey};
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, EthAddress, EventContent, EventData, EventKey, L2ToL1Payload,
    MessageToL1,
};

use crate::execution::entry_point::CallEntryPoint;
use crate::execution::errors::SyscallExecutionError;
use crate::execution::execution_utils::{
    execute_deployment, execute_library_call, felt_from_memory_ptr, ReadOnlySegment,
};
use crate::execution::syscall_handling::{
    execute_inner_call, felt_to_bool, read_call_params, read_calldata, read_felt_array, write_felt,
    SyscallHintProcessor,
};

#[cfg(test)]
#[path = "syscalls_test.rs"]
pub mod test;

pub type SyscallResult<T> = Result<T, SyscallExecutionError>;
pub type WriteResponseResult = SyscallResult<()>;

/// The array metadata contains its size and its starting pointer.
const ARRAY_METADATA_SIZE: usize = 2;

pub trait SyscallRequest: Sized {
    const SIZE: usize;

    fn read(_vm: &VirtualMachine, _ptr: &Relocatable) -> SyscallResult<Self>;
}

pub trait SyscallResponse {
    const SIZE: usize;

    fn write(self, _vm: &mut VirtualMachine, _ptr: &Relocatable) -> WriteResponseResult;
}

// Common structs.

#[derive(Debug, Eq, PartialEq)]
pub struct EmptyRequest;

impl SyscallRequest for EmptyRequest {
    const SIZE: usize = 0;

    fn read(_vm: &VirtualMachine, _ptr: &Relocatable) -> SyscallResult<EmptyRequest> {
        Ok(EmptyRequest)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct EmptyResponse;

impl SyscallResponse for EmptyResponse {
    const SIZE: usize = 0;

    fn write(self, _vm: &mut VirtualMachine, _ptr: &Relocatable) -> WriteResponseResult {
        Ok(())
    }
}

#[derive(Debug)]
pub struct SingleSegmentResponse {
    segment: ReadOnlySegment,
}

impl SyscallResponse for SingleSegmentResponse {
    const SIZE: usize = ARRAY_METADATA_SIZE;

    fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        vm.insert_value(ptr, self.segment.length)?;
        Ok(vm.insert_value(&(ptr + 1), self.segment.start_ptr)?)
    }
}

// StorageRead syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct StorageReadRequest {
    pub address: StorageKey,
}

impl SyscallRequest for StorageReadRequest {
    const SIZE: usize = 1;

    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<StorageReadRequest> {
        let address = StorageKey::try_from(felt_from_memory_ptr(vm, ptr)?)?;
        Ok(StorageReadRequest { address })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct StorageReadResponse {
    pub value: StarkFelt,
}

impl SyscallResponse for StorageReadResponse {
    const SIZE: usize = 1;

    fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        write_felt(vm, ptr, self.value)
    }
}

pub fn storage_read(
    request: StorageReadRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<StorageReadResponse> {
    let value =
        syscall_handler.state.get_storage_at(syscall_handler.storage_address, request.address)?;

    Ok(StorageReadResponse { value: *value })
}

// StorageWrite syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct StorageWriteRequest {
    pub address: StorageKey,
    pub value: StarkFelt,
}

impl SyscallRequest for StorageWriteRequest {
    const SIZE: usize = 2;

    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<StorageWriteRequest> {
        let address = StorageKey::try_from(felt_from_memory_ptr(vm, ptr)?)?;
        let value = felt_from_memory_ptr(vm, &(ptr + 1))?;
        Ok(StorageWriteRequest { address, value })
    }
}

type StorageWriteResponse = EmptyResponse;

pub fn storage_write(
    request: StorageWriteRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<StorageWriteResponse> {
    syscall_handler.state.set_storage_at(
        syscall_handler.storage_address,
        request.address,
        request.value,
    );

    Ok(StorageWriteResponse {})
}

// CallContract syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct CallContractRequest {
    pub contract_address: ContractAddress,
    pub function_selector: EntryPointSelector,
    pub calldata: Calldata,
}

impl SyscallRequest for CallContractRequest {
    const SIZE: usize = 2 + ARRAY_METADATA_SIZE;

    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<CallContractRequest> {
        let contract_address = ContractAddress::try_from(felt_from_memory_ptr(vm, ptr)?)?;
        let (function_selector, calldata) = read_call_params(vm, &(ptr + 1))?;

        Ok(CallContractRequest { contract_address, function_selector, calldata })
    }
}

pub type CallContractResponse = SingleSegmentResponse;

pub fn call_contract(
    request: CallContractRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<CallContractResponse> {
    let entry_point = CallEntryPoint {
        class_hash: None,
        entry_point_type: EntryPointType::External,
        entry_point_selector: request.function_selector,
        calldata: request.calldata,
        storage_address: request.contract_address,
        caller_address: syscall_handler.storage_address,
    };
    let retdata_segment = execute_inner_call(entry_point, vm, syscall_handler)?;

    Ok(CallContractResponse { segment: retdata_segment })
}

// LibraryCall syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct LibraryCallRequest {
    pub class_hash: ClassHash,
    pub function_selector: EntryPointSelector,
    pub calldata: Calldata,
}

impl SyscallRequest for LibraryCallRequest {
    const SIZE: usize = 2 + ARRAY_METADATA_SIZE;

    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<LibraryCallRequest> {
        let class_hash = ClassHash(felt_from_memory_ptr(vm, ptr)?);
        let (function_selector, calldata) = read_call_params(vm, &(ptr + 1))?;

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
        call_to_external,
        request.function_selector,
        request.calldata,
    )?;

    Ok(LibraryCallResponse { segment: retdata_segment })
}

// DelegateCall syscall.

type DelegateCallRequest = CallContractRequest;
type DelegateCallResponse = CallContractResponse;

pub fn delegate_call(
    request: DelegateCallRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<DelegateCallResponse> {
    let call_to_external = true;
    let class_hash = *syscall_handler.state.get_class_hash_at(request.contract_address)?;
    let retdata_segment = execute_library_call(
        syscall_handler,
        vm,
        class_hash,
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
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<DelegateCallResponse> {
    let call_to_external = false;
    let class_hash = *syscall_handler.state.get_class_hash_at(request.contract_address)?;
    let retdata_segment = execute_library_call(
        syscall_handler,
        vm,
        class_hash,
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
    const SIZE: usize = 3 + ARRAY_METADATA_SIZE;

    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<DeployRequest> {
        let class_hash = ClassHash(felt_from_memory_ptr(vm, ptr)?);
        let contract_address_salt = ContractAddressSalt(felt_from_memory_ptr(vm, &(ptr + 1))?);
        let constructor_calldata = read_calldata(vm, &(ptr + 2))?;
        let deploy_from_zero = felt_from_memory_ptr(vm, &(ptr + 2 + ARRAY_METADATA_SIZE))?;

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
    const SIZE: usize = 1 + ARRAY_METADATA_SIZE;

    fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        write_felt(vm, ptr, *self.contract_address.0.key())?;
        vm.insert_value(&(ptr + 1), 0)?;
        Ok(vm.insert_value(&(ptr + 2), 0)?)
    }
}

pub fn deploy(
    request: DeployRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<DeployResponse> {
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

    let call_info = execute_deployment(
        syscall_handler.state,
        syscall_handler.block_context,
        syscall_handler.account_tx_context,
        request.class_hash,
        deployed_contract_address,
        deployer_address,
        request.constructor_calldata,
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
    const SIZE: usize = 2 * ARRAY_METADATA_SIZE;

    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<EmitEventRequest> {
        let keys = read_felt_array(vm, ptr)?.into_iter().map(EventKey).collect();
        let data = EventData(read_felt_array(vm, &(ptr + ARRAY_METADATA_SIZE))?);

        Ok(EmitEventRequest { content: EventContent { keys, data } })
    }
}

type EmitEventResponse = EmptyResponse;

pub fn emit_event(
    request: EmitEventRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<EmptyResponse> {
    syscall_handler.events.push(request.content);

    Ok(EmitEventResponse {})
}

// SendMessageToL1 syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct SendMessageToL1Request {
    pub message: MessageToL1,
}

impl SyscallRequest for SendMessageToL1Request {
    // The Cairo struct contains: `to_address`, `payload_size`, `payload`.
    const SIZE: usize = 1 + ARRAY_METADATA_SIZE;

    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<SendMessageToL1Request> {
        let to_address = EthAddress::try_from(felt_from_memory_ptr(vm, ptr)?)?;
        let payload = L2ToL1Payload(read_felt_array(vm, &(ptr + 1))?);

        Ok(SendMessageToL1Request { message: MessageToL1 { to_address, payload } })
    }
}

type SendMessageToL1Response = EmptyResponse;

pub fn send_message_to_l1(
    request: SendMessageToL1Request,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<EmptyResponse> {
    syscall_handler.l2_to_l1_messages.push(request.message);

    Ok(SendMessageToL1Response {})
}

// GetContractAddress syscall.

type GetContractAddressRequest = EmptyRequest;

#[derive(Debug, Eq, PartialEq)]
pub struct GetContractAddressResponse {
    pub address: ContractAddress,
}

impl SyscallResponse for GetContractAddressResponse {
    const SIZE: usize = 1;

    fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        write_felt(vm, ptr, *self.address.0.key())
    }
}

pub fn get_contract_address(
    _request: GetContractAddressRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<GetContractAddressResponse> {
    Ok(GetContractAddressResponse { address: syscall_handler.storage_address })
}

// GetCallerAddress syscall.

type GetCallerAddressRequest = EmptyRequest;
type GetCallerAddressResponse = GetContractAddressResponse;

pub fn get_caller_address(
    _request: GetCallerAddressRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<GetCallerAddressResponse> {
    Ok(GetCallerAddressResponse { address: syscall_handler.caller_address })
}

// GetSequencerAddress syscall.

type GetSequencerAddressRequest = EmptyRequest;
type GetSequencerAddressResponse = GetContractAddressResponse;

pub fn get_sequencer_address(
    _request: GetSequencerAddressRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<GetSequencerAddressResponse> {
    Ok(GetSequencerAddressResponse { address: syscall_handler.block_context.sequencer_address })
}

// GetBlockNumber syscall.

type GetBlockNumberRequest = EmptyRequest;

#[derive(Debug, Eq, PartialEq)]
pub struct GetBlockNumberResponse {
    pub block_number: BlockNumber,
}

impl SyscallResponse for GetBlockNumberResponse {
    const SIZE: usize = 1;

    fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        Ok(vm.insert_value(ptr, Felt::from(self.block_number.0))?)
    }
}

pub fn get_block_number(
    _request: GetBlockNumberRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<GetBlockNumberResponse> {
    Ok(GetBlockNumberResponse { block_number: syscall_handler.block_context.block_number })
}

// GetBlockTimestamp syscall.

type GetBlockTimestampRequest = EmptyRequest;

#[derive(Debug, Eq, PartialEq)]
pub struct GetBlockTimestampResponse {
    pub block_timestamp: BlockTimestamp,
}

impl SyscallResponse for GetBlockTimestampResponse {
    const SIZE: usize = 1;

    fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        Ok(vm.insert_value(ptr, Felt::from(self.block_timestamp.0))?)
    }
}

pub fn get_block_timestamp(
    _request: GetBlockTimestampRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<GetBlockTimestampResponse> {
    Ok(GetBlockTimestampResponse { block_timestamp: syscall_handler.block_context.block_timestamp })
}

// GetTxSignature syscall.

type GetTxSignatureRequest = EmptyRequest;
type GetTxSignatureResponse = SingleSegmentResponse;

pub fn get_tx_signature(
    _request: GetTxSignatureRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<GetTxSignatureResponse> {
    let start_ptr = syscall_handler.get_or_allocate_tx_signature_segment(vm)?;
    let length = syscall_handler.account_tx_context.signature.0.len();

    Ok(GetTxSignatureResponse { segment: ReadOnlySegment { start_ptr, length } })
}
