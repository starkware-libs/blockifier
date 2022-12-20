use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::vm_core::VirtualMachine;
use starknet_api::core::{ClassHash, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::state::{EntryPointType, StorageKey};
use starknet_api::transaction::CallData;

use crate::execution::entry_point::CallEntryPoint;
use crate::execution::errors::SyscallExecutionError;
use crate::execution::execution_utils::{
    felt_to_bigint, get_felt_from_memory_cell, get_felt_range,
};
use crate::execution::syscall_handling::SyscallHandler;

pub type SyscallResult<T> = Result<T, SyscallExecutionError>;
pub type ReadRequestResult = SyscallResult<SyscallRequest>;
pub type ExecutionResult = SyscallResult<SyscallResponse>;
pub type WriteResponseResult = SyscallResult<()>;

pub const LIBRARY_CALL_SELECTOR_BYTES: &[u8] = b"LibraryCall";
pub const STORAGE_READ_SELECTOR_BYTES: &[u8] = b"StorageRead";
pub const STORAGE_WRITE_SELECTOR_BYTES: &[u8] = b"StorageWrite";

#[derive(Debug, PartialEq, Eq)]
pub struct EmptyResponse {}

impl EmptyResponse {
    pub fn write(self, _vm: &mut VirtualMachine, _ptr: &Relocatable) -> WriteResponseResult {
        Ok(())
    }
}

pub const STORAGE_READ_REQUEST_SIZE: usize = 1;

#[derive(Debug, PartialEq, Eq)]
pub struct StorageReadRequest {
    pub address: StorageKey,
}

impl StorageReadRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let address: StarkFelt = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        let address: StorageKey = address.try_into()?;
        Ok(SyscallRequest::StorageRead(StorageReadRequest { address }))
    }

    pub fn execute(&self, syscall_handler: &mut SyscallHandler) -> ExecutionResult {
        // TODO(AlonH, 21/12/2022): Remove unwrap once errors are created for state.
        let value = syscall_handler
            .state
            .get_storage_at(syscall_handler.storage_address, self.address)
            .unwrap();
        Ok(SyscallResponse::StorageRead(StorageReadResponse { value: *value }))
    }
}

pub const STORAGE_READ_RESPONSE_SIZE: usize = 1;

#[derive(Debug, PartialEq, Eq)]
pub struct StorageReadResponse {
    pub value: StarkFelt,
}

impl StorageReadResponse {
    pub fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        vm.insert_value(ptr, felt_to_bigint(self.value))?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
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

    pub fn execute(&self, syscall_handler: &mut SyscallHandler) -> ExecutionResult {
        syscall_handler.state.set_storage_at(
            syscall_handler.storage_address,
            self.address,
            self.value,
        );
        Ok(SyscallResponse::StorageWrite(EmptyResponse {}))
    }
}

pub const STORAGE_WRITE_RESPONSE_SIZE: usize = 0;

pub type StorageWriteResponse = EmptyResponse;

#[derive(Debug, PartialEq, Eq)]
pub struct CallContractResponse {
    pub retdata_size: StarkFelt,
    pub retdata: Vec<StarkFelt>,
}

pub const CALL_CONTRACT_RESPONSE_SIZE: usize = 2;

impl CallContractResponse {
    pub fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        vm.insert_value(ptr, felt_to_bigint(self.retdata_size))?;

        // Write response payload to the memory.
        let segment = vm.add_memory_segment();
        vm.insert_value(&(ptr + 1), &segment)?;
        let data: Vec<MaybeRelocatable> =
            self.retdata.into_iter().map(|x| felt_to_bigint(x).into()).collect();
        vm.load_data(&segment.into(), data)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct LibraryCallRequest {
    pub class_hash: ClassHash,
    pub function_selector: EntryPointSelector,
    pub calldata: CallData,
}

pub const LIBRARY_CALL_REQUEST_SIZE: usize = 4;

impl LibraryCallRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let class_hash = ClassHash(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?);
        let function_selector =
            EntryPointSelector(get_felt_from_memory_cell(vm.get_maybe(&(ptr + 1))?)?);
        let calldata_size = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 2))?)?;
        let calldata_ptr = match vm.get_maybe(&(ptr + 3))? {
            Some(ptr) => ptr,
            None => return Err(VirtualMachineError::NoneInMemoryRange.into()),
        };
        let calldata = CallData(get_felt_range(vm, &calldata_ptr, calldata_size.try_into()?)?);

        Ok(SyscallRequest::LibraryCall(LibraryCallRequest {
            class_hash,
            function_selector,
            calldata,
        }))
    }

    pub fn execute(self, syscall_handler: &mut SyscallHandler) -> ExecutionResult {
        let entry_point = CallEntryPoint {
            class_hash: self.class_hash,
            entry_point_type: EntryPointType::External,
            entry_point_selector: self.function_selector,
            calldata: self.calldata,
            storage_address: syscall_handler.storage_address,
        };
        let call_info = entry_point.execute(&mut syscall_handler.state)?;
        let retdata = call_info.execution.retdata.clone();
        syscall_handler.inner_calls.push(call_info);

        Ok(SyscallResponse::LibraryCall(LibraryCallResponse {
            retdata_size: StarkFelt::from(retdata.len() as u64),
            retdata,
        }))
    }
}

pub type LibraryCallResponse = CallContractResponse;

pub const LIBRARY_CALL_RESPONSE_SIZE: usize = CALL_CONTRACT_RESPONSE_SIZE;

#[derive(Debug, PartialEq, Eq)]
pub enum SyscallRequest {
    LibraryCall(LibraryCallRequest),
    StorageRead(StorageReadRequest),
    StorageWrite(StorageWriteRequest),
}

impl SyscallRequest {
    pub fn read(selector: StarkFelt, vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let selector_bytes: &[u8] = selector.bytes();
        // Remove leading zero bytes from selector.
        let first_non_zero = selector_bytes.iter().position(|&byte| byte != b'\0').unwrap_or(32);
        match &selector_bytes[first_non_zero..32] {
            LIBRARY_CALL_SELECTOR_BYTES => LibraryCallRequest::read(vm, ptr),
            STORAGE_READ_SELECTOR_BYTES => StorageReadRequest::read(vm, ptr),
            STORAGE_WRITE_SELECTOR_BYTES => StorageWriteRequest::read(vm, ptr),
            _ => Err(SyscallExecutionError::InvalidSyscallSelector(selector)),
        }
    }

    pub fn execute(self, syscall_handler: &mut SyscallHandler) -> ExecutionResult {
        match self {
            SyscallRequest::LibraryCall(request) => request.execute(syscall_handler),
            SyscallRequest::StorageRead(request) => request.execute(syscall_handler),
            SyscallRequest::StorageWrite(request) => request.execute(syscall_handler),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            SyscallRequest::LibraryCall(_) => LIBRARY_CALL_REQUEST_SIZE,
            SyscallRequest::StorageRead(_) => STORAGE_READ_REQUEST_SIZE,
            SyscallRequest::StorageWrite(_) => STORAGE_WRITE_REQUEST_SIZE,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SyscallResponse {
    LibraryCall(LibraryCallResponse),
    StorageRead(StorageReadResponse),
    StorageWrite(EmptyResponse),
}

impl SyscallResponse {
    pub fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        match self {
            SyscallResponse::LibraryCall(response) => response.write(vm, ptr),
            SyscallResponse::StorageRead(response) => response.write(vm, ptr),
            SyscallResponse::StorageWrite(response) => response.write(vm, ptr),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            SyscallResponse::LibraryCall(_) => LIBRARY_CALL_RESPONSE_SIZE,
            SyscallResponse::StorageRead(_) => STORAGE_READ_RESPONSE_SIZE,
            SyscallResponse::StorageWrite(_) => STORAGE_WRITE_RESPONSE_SIZE,
        }
    }
}
