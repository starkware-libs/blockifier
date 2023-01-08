use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::vm_core::VirtualMachine;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::state::{EntryPointType, StorageKey};
use starknet_api::transaction::{
    Calldata, EthAddress, EventContent, EventData, EventKey, L2ToL1Payload, MessageToL1,
};

use crate::execution::contract_address::calculate_contract_address;
use crate::execution::entry_point::{execute_constructor_entry_point, CallEntryPoint, Retdata};
use crate::execution::errors::SyscallExecutionError;
use crate::execution::execution_utils::{get_felt_from_memory_cell, stark_felt_to_felt};
use crate::execution::syscall_handling::{
    execute_inner_call, felt_to_bool, read_call_params, read_calldata, read_felt_array,
    write_retdata, SyscallHintProcessor,
};
use crate::retdata;

#[cfg(test)]
#[path = "syscalls_test.rs"]
pub mod test;

pub type SyscallResult<T> = Result<T, SyscallExecutionError>;
pub type ReadRequestResult = SyscallResult<SyscallRequest>;
pub type SyscallExecutionResult = SyscallResult<SyscallResponse>;
pub type WriteResponseResult = SyscallResult<()>;

pub const CALL_CONTRACT_SELECTOR_BYTES: &[u8] = b"CallContract";
pub const DEPLOY_SELECTOR_BYTES: &[u8] = b"Deploy";
pub const EMIT_EVENT_SELECTOR_BYTES: &[u8] = b"EmitEvent";
pub const GET_CALLER_ADDRESS_SELECTOR_BYTES: &[u8] = b"GetCallerAddress";
pub const GET_CONTRACT_ADDRESS_SELECTOR_BYTES: &[u8] = b"GetContractAddress";
pub const LIBRARY_CALL_SELECTOR_BYTES: &[u8] = b"LibraryCall";
pub const SEND_MESSAGE_TO_L1_SELECTOR_BYTES: &[u8] = b"SendMessageToL1";
pub const STORAGE_READ_SELECTOR_BYTES: &[u8] = b"StorageRead";
pub const STORAGE_WRITE_SELECTOR_BYTES: &[u8] = b"StorageWrite";

// The array metadata contains its size and its starting pointer.
const ARRAY_METADATA_SIZE: usize = 2;

pub trait _SyscallRequest: Sized {
    const SIZE: usize;

    fn read(_vm: &VirtualMachine, _ptr: &Relocatable) -> SyscallResult<Self>;
}

pub trait _SyscallResponse {
    const SIZE: usize;

    fn write(self, _vm: &mut VirtualMachine, _ptr: &Relocatable) -> WriteResponseResult;
}

/// Common structs.

#[derive(Debug, Eq, PartialEq)]
pub struct EmptyRequest;

impl _SyscallRequest for EmptyRequest {
    const SIZE: usize = 0;

    fn read(_vm: &VirtualMachine, _ptr: &Relocatable) -> SyscallResult<EmptyRequest> {
        Ok(EmptyRequest)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct EmptyResponse;

impl _SyscallResponse for EmptyResponse {
    const SIZE: usize = 0;

    fn write(self, _vm: &mut VirtualMachine, _ptr: &Relocatable) -> WriteResponseResult {
        Ok(())
    }
}

impl EmptyResponse {
    pub fn write(self, _vm: &mut VirtualMachine, _ptr: &Relocatable) -> WriteResponseResult {
        Ok(())
    }
}

pub const EMPTY_RESPONSE_SIZE: usize = 0;

/// StorageRead syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct StorageReadRequest {
    pub address: StorageKey,
}

impl _SyscallRequest for StorageReadRequest {
    const SIZE: usize = 1;

    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<StorageReadRequest> {
        let address = StorageKey::try_from(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?)?;
        Ok(StorageReadRequest { address })
    }
}

// TODO(AlonH, 21/12/2022): Couple all size constants with Cairo structs from the code.
pub const STORAGE_READ_REQUEST_SIZE: usize = 1;

impl StorageReadRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let address: StarkFelt = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        let address: StorageKey = address.try_into()?;
        Ok(SyscallRequest::StorageRead(StorageReadRequest { address }))
    }

    pub fn execute(self, syscall_handler: &mut SyscallHintProcessor<'_>) -> SyscallExecutionResult {
        let value =
            syscall_handler.state.get_storage_at(syscall_handler.storage_address, self.address)?;
        Ok(SyscallResponse::StorageRead(StorageReadResponse { value: *value }))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct StorageReadResponse {
    pub value: StarkFelt,
}

impl _SyscallResponse for StorageReadResponse {
    const SIZE: usize = 1;

    fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        Ok(vm.insert_value(ptr, stark_felt_to_felt(self.value))?)
    }
}

pub const STORAGE_READ_RESPONSE_SIZE: usize = 1;

impl StorageReadResponse {
    pub fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        vm.insert_value(ptr, stark_felt_to_felt(self.value))?;
        Ok(())
    }
}

pub fn storage_read(
    request: StorageReadRequest,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<StorageReadResponse> {
    let value =
        syscall_handler.state.get_storage_at(syscall_handler.storage_address, request.address)?;
    Ok(StorageReadResponse { value: *value })
}

/// StorageWrite syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct StorageWriteRequest {
    pub address: StorageKey,
    pub value: StarkFelt,
}

impl _SyscallRequest for StorageWriteRequest {
    const SIZE: usize = 2;

    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<StorageWriteRequest> {
        let address = StorageKey::try_from(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?)?;
        let value = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 1))?)?;
        Ok(StorageWriteRequest { address, value })
    }
}

pub const STORAGE_WRITE_REQUEST_SIZE: usize = 2;

impl StorageWriteRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let address: StarkFelt = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        let address: StorageKey = address.try_into()?;
        let value = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 1))?)?;
        Ok(SyscallRequest::StorageWrite(StorageWriteRequest { address, value }))
    }

    pub fn execute(self, syscall_handler: &mut SyscallHintProcessor<'_>) -> SyscallExecutionResult {
        syscall_handler.state.set_storage_at(
            syscall_handler.storage_address,
            self.address,
            self.value,
        );
        Ok(SyscallResponse::StorageWrite(EmptyResponse))
    }
}

pub const STORAGE_WRITE_RESPONSE_SIZE: usize = EMPTY_RESPONSE_SIZE;

pub fn storage_write(
    request: StorageWriteRequest,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<EmptyResponse> {
    syscall_handler.state.set_storage_at(
        syscall_handler.storage_address,
        request.address,
        request.value,
    );
    Ok(EmptyResponse)
}

/// CallContract syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct CallContractRequest {
    pub contract_address: ContractAddress,
    pub function_selector: EntryPointSelector,
    pub calldata: Calldata,
}

impl _SyscallRequest for CallContractRequest {
    const SIZE: usize = 2 + ARRAY_METADATA_SIZE;

    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<CallContractRequest> {
        let contract_address =
            ContractAddress::try_from(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?)?;
        let (function_selector, calldata) = read_call_params(vm, &(ptr + 1))?;

        Ok(CallContractRequest { contract_address, function_selector, calldata })
    }
}

pub const CALL_CONTRACT_REQUEST_SIZE: usize = 4;

impl CallContractRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let contract_address =
            ContractAddress(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?.try_into()?);
        let (function_selector, calldata) = read_call_params(vm, &(ptr + 1))?;

        Ok(SyscallRequest::CallContract(CallContractRequest {
            contract_address,
            function_selector,
            calldata,
        }))
    }

    pub fn execute(self, syscall_handler: &mut SyscallHintProcessor<'_>) -> SyscallExecutionResult {
        let entry_point = CallEntryPoint {
            class_hash: None,
            entry_point_type: EntryPointType::External,
            entry_point_selector: self.function_selector,
            calldata: self.calldata,
            storage_address: self.contract_address,
            caller_address: syscall_handler.storage_address,
        };
        let retdata = execute_inner_call(entry_point, syscall_handler)?;

        Ok(SyscallResponse::CallContract(CallContractResponse { retdata }))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct CallContractResponse {
    pub retdata: Retdata,
}

impl _SyscallResponse for CallContractResponse {
    const SIZE: usize = ARRAY_METADATA_SIZE;

    fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        write_retdata(vm, ptr, self.retdata)
    }
}

pub const CALL_CONTRACT_RESPONSE_SIZE: usize = 2;

impl CallContractResponse {
    pub fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        write_retdata(vm, ptr, self.retdata)
    }
}

pub fn call_contract(
    request: CallContractRequest,
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
    let retdata = execute_inner_call(entry_point, syscall_handler)?;

    Ok(CallContractResponse { retdata })
}

/// LibraryCall syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct LibraryCallRequest {
    pub class_hash: ClassHash,
    pub function_selector: EntryPointSelector,
    pub calldata: Calldata,
}

impl _SyscallRequest for LibraryCallRequest {
    const SIZE: usize = 2 + ARRAY_METADATA_SIZE;

    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<LibraryCallRequest> {
        let class_hash = ClassHash(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?);
        let (function_selector, calldata) = read_call_params(vm, &(ptr + 1))?;

        Ok(LibraryCallRequest { class_hash, function_selector, calldata })
    }
}

pub const LIBRARY_CALL_REQUEST_SIZE: usize = 4;

impl LibraryCallRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let class_hash = ClassHash(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?);
        let (function_selector, calldata) = read_call_params(vm, &(ptr + 1))?;

        Ok(SyscallRequest::LibraryCall(LibraryCallRequest {
            class_hash,
            function_selector,
            calldata,
        }))
    }

    pub fn execute(self, syscall_handler: &mut SyscallHintProcessor<'_>) -> SyscallExecutionResult {
        let entry_point = CallEntryPoint {
            class_hash: Some(self.class_hash),
            entry_point_type: EntryPointType::External,
            entry_point_selector: self.function_selector,
            calldata: self.calldata,
            // The call context remains the same in a library call.
            storage_address: syscall_handler.storage_address,
            caller_address: syscall_handler.caller_address,
        };
        let retdata = execute_inner_call(entry_point, syscall_handler)?;

        Ok(SyscallResponse::LibraryCall(LibraryCallResponse { retdata }))
    }
}

pub type LibraryCallResponse = CallContractResponse;

pub const LIBRARY_CALL_RESPONSE_SIZE: usize = CALL_CONTRACT_RESPONSE_SIZE;

pub fn library_call(
    request: LibraryCallRequest,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<CallContractResponse> {
    let entry_point = CallEntryPoint {
        class_hash: Some(request.class_hash),
        entry_point_type: EntryPointType::External,
        entry_point_selector: request.function_selector,
        calldata: request.calldata,
        // The call context remains the same in a library call.
        storage_address: syscall_handler.storage_address,
        caller_address: syscall_handler.caller_address,
    };
    let retdata = execute_inner_call(entry_point, syscall_handler)?;

    Ok(CallContractResponse { retdata })
}

/// Deploy syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct DeployRequest {
    pub class_hash: ClassHash,
    pub contract_address_salt: StarkFelt,
    pub constructor_calldata: Calldata,
    pub deploy_from_zero: bool,
}

impl _SyscallRequest for DeployRequest {
    const SIZE: usize = 3 + ARRAY_METADATA_SIZE;

    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<DeployRequest> {
        let class_hash = ClassHash(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?);
        let contract_address_salt = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 1))?)?;
        let constructor_calldata = read_calldata(vm, &(ptr + 2))?;
        let deploy_from_zero =
            get_felt_from_memory_cell(vm.get_maybe(&(ptr + 2 + ARRAY_METADATA_SIZE))?)?;

        Ok(DeployRequest {
            class_hash,
            contract_address_salt,
            constructor_calldata,
            deploy_from_zero: felt_to_bool(deploy_from_zero)?,
        })
    }
}

pub const DEPLOY_REQUEST_SIZE: usize = 5;

impl DeployRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let class_hash = ClassHash(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?);
        let contract_address_salt = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 1))?)?;
        let constructor_calldata = read_calldata(vm, &(ptr + 2))?;
        let next_ptr = ptr + 2 + ARRAY_METADATA_SIZE;
        let deploy_from_zero = felt_to_bool(get_felt_from_memory_cell(vm.get_maybe(&next_ptr)?)?)?;

        Ok(SyscallRequest::Deploy(DeployRequest {
            class_hash,
            contract_address_salt,
            constructor_calldata,
            deploy_from_zero,
        }))
    }

    pub fn execute(self, syscall_handler: &mut SyscallHintProcessor<'_>) -> SyscallExecutionResult {
        let deployer_address = syscall_handler.storage_address;
        let deployer_address_for_calculation = match self.deploy_from_zero {
            true => ContractAddress::default(),
            false => deployer_address,
        };
        let deployed_contract_address = calculate_contract_address(
            self.contract_address_salt,
            self.class_hash,
            &self.constructor_calldata,
            deployer_address_for_calculation,
        )?;

        // Address allocation in the state is done before calling the constructor, so that it is
        // visible from it.
        syscall_handler.state.set_class_hash_at(deployed_contract_address, self.class_hash)?;
        let call_info = execute_constructor_entry_point(
            syscall_handler.state,
            syscall_handler.block_context,
            syscall_handler.account_tx_context,
            self.class_hash,
            deployed_contract_address,
            deployer_address,
            self.constructor_calldata,
        )?;
        syscall_handler.inner_calls.push(call_info);

        Ok(SyscallResponse::Deploy(DeployResponse { contract_address: deployed_contract_address }))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct DeployResponse {
    pub contract_address: ContractAddress,
}

impl _SyscallResponse for DeployResponse {
    // The Cairo struct contains: `contract_address`, `constructor_retdata_size`,
    // `constructor_retdata`.
    // Nonempty constructor retdata is currently not supported.
    const SIZE: usize = 1 + ARRAY_METADATA_SIZE;

    fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        vm.insert_value(ptr, stark_felt_to_felt(*self.contract_address.0.key()))?;
        write_retdata(vm, ptr, retdata![])
    }
}

pub const DEPLOY_RESPONSE_SIZE: usize = 3;

impl DeployResponse {
    pub fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        vm.insert_value(ptr, stark_felt_to_felt(*self.contract_address.0.key()))?;
        write_retdata(vm, &(ptr + 1), retdata![])
    }
}

pub fn deploy(
    request: DeployRequest,
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

    // Address allocation in the state is done before calling the constructor, so that it is
    // visible from it.
    syscall_handler.state.set_class_hash_at(deployed_contract_address, request.class_hash)?;
    let call_info = execute_constructor_entry_point(
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

/// EmitEvent syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct EmitEventRequest {
    pub content: EventContent,
}

impl _SyscallRequest for EmitEventRequest {
    // The Cairo struct contains: `keys_len`, `keys`, `data_len`, `data`·
    const SIZE: usize = 2 * ARRAY_METADATA_SIZE;

    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<EmitEventRequest> {
        let keys = read_felt_array(vm, ptr)?.into_iter().map(EventKey).collect();
        let data = EventData(read_felt_array(vm, &(ptr + ARRAY_METADATA_SIZE))?);

        Ok(EmitEventRequest { content: EventContent { keys, data } })
    }
}

pub const EMIT_EVENT_REQUEST_SIZE: usize = 4;

impl EmitEventRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let keys = read_felt_array(vm, ptr)?.into_iter().map(EventKey).collect();
        let data = EventData(read_felt_array(vm, &(ptr + ARRAY_METADATA_SIZE))?);
        let content = EventContent { keys, data };

        Ok(SyscallRequest::EmitEvent(EmitEventRequest { content }))
    }

    pub fn execute(self, syscall_handler: &mut SyscallHintProcessor<'_>) -> SyscallExecutionResult {
        syscall_handler.events.push(self.content);
        Ok(SyscallResponse::EmitEvent(EmptyResponse))
    }
}

pub const EMIT_EVENT_RESPONSE_SIZE: usize = EMPTY_RESPONSE_SIZE;

pub fn emit_event(
    request: EmitEventRequest,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<EmptyResponse> {
    syscall_handler.events.push(request.content);
    Ok(EmptyResponse)
}

/// SendMessageToL1 syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct SendMessageToL1Request {
    pub message: MessageToL1,
}

impl _SyscallRequest for SendMessageToL1Request {
    // The Cairo struct contains: `to_address`, `payload_size`, `payload`.
    const SIZE: usize = 1 + ARRAY_METADATA_SIZE;

    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> SyscallResult<SendMessageToL1Request> {
        let to_address = EthAddress::try_from(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?)?;
        let payload = L2ToL1Payload(read_felt_array(vm, &(ptr + 1))?);

        Ok(SendMessageToL1Request { message: MessageToL1 { to_address, payload } })
    }
}

pub const SEND_MESSAGE_TO_L1_REQUEST_SIZE: usize = 3;

impl SendMessageToL1Request {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let to_address = EthAddress::try_from(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?)?;
        let payload = L2ToL1Payload(read_felt_array(vm, &(ptr + 1))?);
        let message = MessageToL1 { to_address, payload };

        Ok(SyscallRequest::SendMessageToL1(SendMessageToL1Request { message }))
    }

    pub fn execute(self, syscall_handler: &mut SyscallHintProcessor<'_>) -> SyscallExecutionResult {
        syscall_handler.l2_to_l1_messages.push(self.message);
        Ok(SyscallResponse::SendMessageToL1(EmptyResponse))
    }
}

pub const SEND_MESSAGE_TO_L1_RESPONSE_SIZE: usize = EMPTY_RESPONSE_SIZE;

pub fn send_message_to_l1(
    request: SendMessageToL1Request,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<EmptyResponse> {
    syscall_handler.l2_to_l1_messages.push(request.message);
    Ok(EmptyResponse)
}

/// GetCallerAddress syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct GetCallerAddressRequest;

pub const GET_CALLER_ADDRESS_REQUEST_SIZE: usize = 0;

impl GetCallerAddressRequest {
    pub fn read(_vm: &VirtualMachine, _ptr: &Relocatable) -> ReadRequestResult {
        Ok(SyscallRequest::GetCallerAddress(GetCallerAddressRequest))
    }

    pub fn execute(self, syscall_handler: &mut SyscallHintProcessor<'_>) -> SyscallExecutionResult {
        Ok(SyscallResponse::GetCallerAddress(GetCallerAddressResponse {
            address: syscall_handler.caller_address,
        }))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct GetCallerAddressResponse {
    pub address: ContractAddress,
}

impl _SyscallResponse for GetCallerAddressResponse {
    const SIZE: usize = 1;

    fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        Ok(vm.insert_value(ptr, stark_felt_to_felt(*self.address.0.key()))?)
    }
}

pub const GET_CALLER_ADDRESS_RESPONSE_SIZE: usize = 1;

impl GetCallerAddressResponse {
    pub fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        vm.insert_value(ptr, stark_felt_to_felt(*self.address.0.key()))?;
        Ok(())
    }
}

pub fn get_caller_address(
    _request: EmptyRequest,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<GetCallerAddressResponse> {
    Ok(GetCallerAddressResponse { address: syscall_handler.caller_address })
}

/// GetContractAddress syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct GetContractAddressRequest;

pub const GET_CONTRACT_ADDRESS_REQUEST_SIZE: usize = 0;

impl GetContractAddressRequest {
    pub fn read(_vm: &VirtualMachine, _ptr: &Relocatable) -> ReadRequestResult {
        Ok(SyscallRequest::GetContractAddress(GetContractAddressRequest))
    }

    pub fn execute(self, syscall_handler: &mut SyscallHintProcessor<'_>) -> SyscallExecutionResult {
        Ok(SyscallResponse::GetContractAddress(GetContractAddressResponse {
            address: syscall_handler.storage_address,
        }))
    }
}

pub type GetContractAddressResponse = GetCallerAddressResponse;
pub const GET_CONTRACT_ADDRESS_RESPONSE_SIZE: usize = GET_CALLER_ADDRESS_RESPONSE_SIZE;

pub fn get_contract_address(
    _request: EmptyRequest,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<GetCallerAddressResponse> {
    Ok(GetCallerAddressResponse { address: syscall_handler.storage_address })
}

#[derive(Debug, Eq, PartialEq)]
pub enum SyscallRequest {
    CallContract(CallContractRequest),
    Deploy(DeployRequest),
    EmitEvent(EmitEventRequest),
    GetCallerAddress(GetCallerAddressRequest),
    GetContractAddress(GetContractAddressRequest),
    LibraryCall(LibraryCallRequest),
    SendMessageToL1(SendMessageToL1Request),
    StorageRead(StorageReadRequest),
    StorageWrite(StorageWriteRequest),
}

impl SyscallRequest {
    pub fn read(selector: StarkFelt, vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let selector_bytes: &[u8] = selector.bytes();
        // Remove leading zero bytes from selector.
        let first_non_zero = selector_bytes.iter().position(|&byte| byte != b'\0').unwrap_or(32);
        match &selector_bytes[first_non_zero..32] {
            CALL_CONTRACT_SELECTOR_BYTES => CallContractRequest::read(vm, ptr),
            DEPLOY_SELECTOR_BYTES => DeployRequest::read(vm, ptr),
            EMIT_EVENT_SELECTOR_BYTES => EmitEventRequest::read(vm, ptr),
            GET_CALLER_ADDRESS_SELECTOR_BYTES => GetCallerAddressRequest::read(vm, ptr),
            GET_CONTRACT_ADDRESS_SELECTOR_BYTES => GetContractAddressRequest::read(vm, ptr),
            LIBRARY_CALL_SELECTOR_BYTES => LibraryCallRequest::read(vm, ptr),
            SEND_MESSAGE_TO_L1_SELECTOR_BYTES => SendMessageToL1Request::read(vm, ptr),
            STORAGE_READ_SELECTOR_BYTES => StorageReadRequest::read(vm, ptr),
            STORAGE_WRITE_SELECTOR_BYTES => StorageWriteRequest::read(vm, ptr),
            _ => Err(SyscallExecutionError::InvalidSyscallSelector(selector)),
        }
    }

    pub fn execute(self, syscall_handler: &mut SyscallHintProcessor<'_>) -> SyscallExecutionResult {
        match self {
            SyscallRequest::CallContract(request) => request.execute(syscall_handler),
            SyscallRequest::Deploy(request) => request.execute(syscall_handler),
            SyscallRequest::EmitEvent(request) => request.execute(syscall_handler),
            SyscallRequest::GetCallerAddress(request) => request.execute(syscall_handler),
            SyscallRequest::GetContractAddress(request) => request.execute(syscall_handler),
            SyscallRequest::LibraryCall(request) => request.execute(syscall_handler),
            SyscallRequest::SendMessageToL1(request) => request.execute(syscall_handler),
            SyscallRequest::StorageRead(request) => request.execute(syscall_handler),
            SyscallRequest::StorageWrite(request) => request.execute(syscall_handler),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            SyscallRequest::CallContract(_) => CALL_CONTRACT_REQUEST_SIZE,
            SyscallRequest::Deploy(_) => DEPLOY_REQUEST_SIZE,
            SyscallRequest::EmitEvent(_) => EMIT_EVENT_REQUEST_SIZE,
            SyscallRequest::GetCallerAddress(_) => GET_CALLER_ADDRESS_REQUEST_SIZE,
            SyscallRequest::GetContractAddress(_) => GET_CONTRACT_ADDRESS_REQUEST_SIZE,
            SyscallRequest::LibraryCall(_) => LIBRARY_CALL_REQUEST_SIZE,
            SyscallRequest::SendMessageToL1(_) => SEND_MESSAGE_TO_L1_REQUEST_SIZE,
            SyscallRequest::StorageRead(_) => STORAGE_READ_REQUEST_SIZE,
            SyscallRequest::StorageWrite(_) => STORAGE_WRITE_REQUEST_SIZE,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SyscallResponse {
    CallContract(CallContractResponse),
    Deploy(DeployResponse),
    EmitEvent(EmptyResponse),
    GetCallerAddress(GetCallerAddressResponse),
    GetContractAddress(GetContractAddressResponse),
    LibraryCall(LibraryCallResponse),
    SendMessageToL1(EmptyResponse),
    StorageRead(StorageReadResponse),
    StorageWrite(EmptyResponse),
}

impl SyscallResponse {
    pub fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        match self {
            SyscallResponse::CallContract(response) => response.write(vm, ptr),
            SyscallResponse::Deploy(response) => response.write(vm, ptr),
            SyscallResponse::EmitEvent(response) => response.write(vm, ptr),
            SyscallResponse::GetCallerAddress(response) => response.write(vm, ptr),
            SyscallResponse::GetContractAddress(response) => response.write(vm, ptr),
            SyscallResponse::LibraryCall(response) => response.write(vm, ptr),
            SyscallResponse::SendMessageToL1(response) => response.write(vm, ptr),
            SyscallResponse::StorageRead(response) => response.write(vm, ptr),
            SyscallResponse::StorageWrite(response) => response.write(vm, ptr),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            SyscallResponse::CallContract(_) => CALL_CONTRACT_RESPONSE_SIZE,
            SyscallResponse::Deploy(_) => DEPLOY_RESPONSE_SIZE,
            SyscallResponse::EmitEvent(_) => EMIT_EVENT_RESPONSE_SIZE,
            SyscallResponse::GetCallerAddress(_) => GET_CALLER_ADDRESS_RESPONSE_SIZE,
            SyscallResponse::GetContractAddress(_) => GET_CONTRACT_ADDRESS_RESPONSE_SIZE,
            SyscallResponse::LibraryCall(_) => LIBRARY_CALL_RESPONSE_SIZE,
            SyscallResponse::SendMessageToL1(_) => SEND_MESSAGE_TO_L1_RESPONSE_SIZE,
            SyscallResponse::StorageRead(_) => STORAGE_READ_RESPONSE_SIZE,
            SyscallResponse::StorageWrite(_) => STORAGE_WRITE_RESPONSE_SIZE,
        }
    }
}
