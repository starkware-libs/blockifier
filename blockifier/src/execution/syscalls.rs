use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::vm_core::VirtualMachine;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::state::{EntryPointType, StorageKey};
use starknet_api::transaction::{
    CallData, EthAddress, EventContent, EventData, EventKey, L2ToL1Payload, MessageToL1,
};

use crate::execution::contract_address::calculate_contract_address;
use crate::execution::entry_point::{execute_constructor_entry_point, CallEntryPoint, RetData};
use crate::execution::errors::SyscallExecutionError;
use crate::execution::execution_utils::{felt_to_bigint, get_felt_from_memory_cell};
use crate::execution::syscall_handling::{
    execute_inner_call, felt_to_bool, read_call_params, read_calldata, read_felt_array,
    write_retdata, SyscallHintProcessor,
};
use crate::state::state_reader::StateReader;

pub type SyscallResult<T> = Result<T, SyscallExecutionError>;
pub type ReadRequestResult = SyscallResult<SyscallRequest>;
pub type SyscallExecutionResult = SyscallResult<SyscallResponse>;
pub type WriteResponseResult = SyscallResult<()>;

pub const CALL_CONTRACT_SELECTOR_BYTES: &[u8] = b"CallContract";
pub const DEPLOY_SELECTOR_BYTES: &[u8] = b"Deploy";
pub const EMIT_EVENT_SELECTOR_BYTES: &[u8] = b"EmitEvent";
pub const LIBRARY_CALL_SELECTOR_BYTES: &[u8] = b"LibraryCall";
pub const SEND_MESSAGE_TO_L1_SELECTOR_BYTES: &[u8] = b"SendMessageToL1";
pub const STORAGE_READ_SELECTOR_BYTES: &[u8] = b"StorageRead";
pub const STORAGE_WRITE_SELECTOR_BYTES: &[u8] = b"StorageWrite";

// The array metadata contains its size and its starting pointer.
const ARRAY_METADATA_SIZE: i32 = 2;

#[derive(Debug, Eq, PartialEq)]
pub struct EmptyResponse;

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

// TODO(AlonH, 21/12/2022): Couple all size constants with Cairo structs from the code.
pub const STORAGE_READ_REQUEST_SIZE: usize = 1;

impl StorageReadRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let address: StarkFelt = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        let address: StorageKey = address.try_into()?;
        Ok(SyscallRequest::StorageRead(StorageReadRequest { address }))
    }

    pub fn execute<SR: StateReader>(
        self,
        syscall_handler: &mut SyscallHintProcessor<'_, SR>,
    ) -> SyscallExecutionResult {
        let value =
            syscall_handler.state.get_storage_at(syscall_handler.storage_address, self.address)?;
        Ok(SyscallResponse::StorageRead(StorageReadResponse { value: *value }))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct StorageReadResponse {
    pub value: StarkFelt,
}

pub const STORAGE_READ_RESPONSE_SIZE: usize = 1;

impl StorageReadResponse {
    pub fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        vm.insert_value(ptr, felt_to_bigint(self.value))?;
        Ok(())
    }
}

/// StorageWrite syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct StorageWriteRequest {
    pub address: StorageKey,
    pub value: StarkFelt,
}

pub const STORAGE_WRITE_REQUEST_SIZE: usize = 2;

impl StorageWriteRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let address: StarkFelt = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        let address: StorageKey = address.try_into()?;
        let value = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 1))?)?;
        Ok(SyscallRequest::StorageWrite(StorageWriteRequest { address, value }))
    }

    pub fn execute<SR: StateReader>(
        self,
        syscall_handler: &mut SyscallHintProcessor<'_, SR>,
    ) -> SyscallExecutionResult {
        syscall_handler.state.set_storage_at(
            syscall_handler.storage_address,
            self.address,
            self.value,
        );
        Ok(SyscallResponse::StorageWrite(EmptyResponse))
    }
}

pub const STORAGE_WRITE_RESPONSE_SIZE: usize = EMPTY_RESPONSE_SIZE;

/// CallContract syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct CallContractRequest {
    pub contract_address: ContractAddress,
    pub function_selector: EntryPointSelector,
    pub calldata: CallData,
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

    pub fn execute<SR: StateReader>(
        self,
        syscall_handler: &mut SyscallHintProcessor<'_, SR>,
    ) -> SyscallExecutionResult {
        let class_hash = *syscall_handler.state.get_class_hash_at(self.contract_address)?;
        let entry_point = CallEntryPoint {
            class_hash,
            entry_point_type: EntryPointType::External,
            entry_point_selector: self.function_selector,
            calldata: self.calldata,
            storage_address: self.contract_address,
        };
        let retdata = execute_inner_call(entry_point, syscall_handler)?;

        Ok(SyscallResponse::CallContract(CallContractResponse { retdata }))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct CallContractResponse {
    pub retdata: RetData,
}

pub const CALL_CONTRACT_RESPONSE_SIZE: usize = 2;

impl CallContractResponse {
    pub fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        write_retdata(vm, ptr, self.retdata)
    }
}

/// LibraryCall syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct LibraryCallRequest {
    pub class_hash: ClassHash,
    pub function_selector: EntryPointSelector,
    pub calldata: CallData,
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

    pub fn execute<SR: StateReader>(
        self,
        syscall_handler: &mut SyscallHintProcessor<'_, SR>,
    ) -> SyscallExecutionResult {
        let entry_point = CallEntryPoint {
            class_hash: self.class_hash,
            entry_point_type: EntryPointType::External,
            entry_point_selector: self.function_selector,
            calldata: self.calldata,
            storage_address: syscall_handler.storage_address,
        };
        let retdata = execute_inner_call(entry_point, syscall_handler)?;

        Ok(SyscallResponse::LibraryCall(LibraryCallResponse { retdata }))
    }
}

pub type LibraryCallResponse = CallContractResponse;

pub const LIBRARY_CALL_RESPONSE_SIZE: usize = CALL_CONTRACT_RESPONSE_SIZE;

/// Deploy syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct DeployRequest {
    pub class_hash: ClassHash,
    pub contract_address_salt: StarkFelt,
    pub constructor_calldata: CallData,
    pub deploy_from_zero: bool,
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

    pub fn execute<SR: StateReader>(
        self,
        syscall_handler: &mut SyscallHintProcessor<'_, SR>,
    ) -> SyscallExecutionResult {
        let deployer_address = match self.deploy_from_zero {
            true => ContractAddress::default(),
            false => syscall_handler.storage_address,
        };
        let contract_address = calculate_contract_address(
            self.contract_address_salt,
            self.class_hash,
            &self.constructor_calldata,
            deployer_address,
        )?;

        // Address allocation in the state is done before calling the constructor, so that it is
        // visible from it.
        syscall_handler.state.set_contract_hash(contract_address, self.class_hash)?;
        let call_info = execute_constructor_entry_point(
            syscall_handler.state,
            self.class_hash,
            contract_address,
            self.constructor_calldata,
        )?;
        syscall_handler.inner_calls.push(call_info);

        Ok(SyscallResponse::Deploy(DeployResponse { contract_address }))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct DeployResponse {
    pub contract_address: ContractAddress,
}

// The Cairo struct contains three fields: `contract_address`, `constructor_retdata_size`,
// `constructor_retdata`.
// Nonempty c-tor retdata is currently not supported.
pub const DEPLOY_RESPONSE_SIZE: usize = 3;

impl DeployResponse {
    pub fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        vm.insert_value(ptr, felt_to_bigint(*self.contract_address.0.key()))?;
        write_retdata(vm, &(ptr + 1), RetData(vec![].into()))
    }
}

/// EmitEvent syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct EmitEventRequest {
    pub content: EventContent,
}

// The Cairo struct contains four fields (other than `selector`): `keys_len`, `keys`, `data_len`,
// `data`·
pub const EMIT_EVENT_REQUEST_SIZE: usize = 4;

impl EmitEventRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let keys = read_felt_array(vm, ptr)?.into_iter().map(EventKey).collect();
        let data = EventData(read_felt_array(vm, &(ptr + ARRAY_METADATA_SIZE))?);
        let content = EventContent { keys, data };

        Ok(SyscallRequest::EmitEvent(EmitEventRequest { content }))
    }

    pub fn execute<SR: StateReader>(
        self,
        syscall_handler: &mut SyscallHintProcessor<'_, SR>,
    ) -> SyscallExecutionResult {
        syscall_handler.events.push(self.content);
        Ok(SyscallResponse::EmitEvent(EmptyResponse))
    }
}

pub const EMIT_EVENT_RESPONSE_SIZE: usize = EMPTY_RESPONSE_SIZE;

/// SendMessageToL1 syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct SendMessageToL1Request {
    pub message: MessageToL1,
}

// The Cairo struct contains three fields: `to_address`, `payload_size`, `payload_ptr`.
pub const SEND_MESSAGE_TO_L1_REQUEST_SIZE: usize = 3;

impl SendMessageToL1Request {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let to_address = EthAddress::try_from(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?)?;
        let payload = L2ToL1Payload(read_felt_array(vm, &(ptr + 1))?);
        let message = MessageToL1 { to_address, payload };

        Ok(SyscallRequest::SendMessageToL1(SendMessageToL1Request { message }))
    }

    pub fn execute<SR: StateReader>(
        self,
        syscall_handler: &mut SyscallHintProcessor<'_, SR>,
    ) -> SyscallExecutionResult {
        syscall_handler.l2_to_l1_messages.push(self.message);
        Ok(SyscallResponse::SendMessageToL1(EmptyResponse))
    }
}

pub const SEND_MESSAGE_TO_L1_RESPONSE_SIZE: usize = EMPTY_RESPONSE_SIZE;

#[derive(Debug, Eq, PartialEq)]
pub enum SyscallRequest {
    CallContract(CallContractRequest),
    Deploy(DeployRequest),
    EmitEvent(EmitEventRequest),
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
            LIBRARY_CALL_SELECTOR_BYTES => LibraryCallRequest::read(vm, ptr),
            SEND_MESSAGE_TO_L1_SELECTOR_BYTES => SendMessageToL1Request::read(vm, ptr),
            STORAGE_READ_SELECTOR_BYTES => StorageReadRequest::read(vm, ptr),
            STORAGE_WRITE_SELECTOR_BYTES => StorageWriteRequest::read(vm, ptr),
            _ => Err(SyscallExecutionError::InvalidSyscallSelector(selector)),
        }
    }

    pub fn execute<SR: StateReader>(
        self,
        syscall_handler: &mut SyscallHintProcessor<'_, SR>,
    ) -> SyscallExecutionResult {
        match self {
            SyscallRequest::CallContract(request) => request.execute(syscall_handler),
            SyscallRequest::Deploy(request) => request.execute(syscall_handler),
            SyscallRequest::EmitEvent(request) => request.execute(syscall_handler),
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
            SyscallResponse::LibraryCall(_) => LIBRARY_CALL_RESPONSE_SIZE,
            SyscallResponse::SendMessageToL1(_) => SEND_MESSAGE_TO_L1_RESPONSE_SIZE,
            SyscallResponse::StorageRead(_) => STORAGE_READ_RESPONSE_SIZE,
            SyscallResponse::StorageWrite(_) => STORAGE_WRITE_RESPONSE_SIZE,
        }
    }
}
