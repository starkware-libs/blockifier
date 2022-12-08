use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::vm_core::VirtualMachine;
use starknet_api::hash::StarkFelt;

use crate::execution::entry_point::EntryPointResult;
use crate::execution::errors::SyscallExecutionError;
use crate::execution::execution_utils::{felt_to_bigint, get_felt_from_memory_cell};
use crate::execution::syscall_handling::SyscallHandler;

pub type ReadRequestResult = EntryPointResult<SyscallRequest>;
pub type ExecutionResult = EntryPointResult<SyscallResponse>;
pub type WriteResponseResult = EntryPointResult<()>;

pub const STORAGE_READ_SELECTOR_BYTES: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 116, 111, 114, 97, 103, 101,
    82, 101, 97, 100,
];
pub const STORAGE_WRITE_SELECTOR_BYTES: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 116, 111, 114, 97, 103, 101,
    87, 114, 105, 116, 101,
];

#[derive(Debug, PartialEq, Eq)]
pub struct EmptyResponse {}

impl EmptyResponse {
    pub fn write(&self, _vm: &mut VirtualMachine, _ptr: &Relocatable) -> WriteResponseResult {
        Ok(())
    }
}

pub const STORAGE_READ_REQUEST_SIZE: usize = 1;

#[derive(Debug, PartialEq, Eq)]
pub struct StorageReadRequest {
    pub address: StarkFelt,
}

impl StorageReadRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let address = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        Ok(SyscallRequest::StorageRead(StorageReadRequest { address }))
    }

    pub fn execute(&self, _syscall_handler: &SyscallHandler) -> ExecutionResult {
        // TODO(AlonH, 21/12/2022): Perform state read.
        let value = StarkFelt::from(17);
        Ok(SyscallResponse::Read(StorageReadResponse { value }))
    }
}

pub const STORAGE_READ_RESPONSE_SIZE: usize = 1;

#[derive(Debug, PartialEq, Eq)]
pub struct StorageReadResponse {
    pub value: StarkFelt,
}

impl StorageReadResponse {
    pub fn write(&self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        vm.insert_value(ptr, felt_to_bigint(self.value))?;
        Ok(())
    }
}

pub struct StorageRead {
    pub request: StorageReadRequest,
    pub response: StorageReadResponse,
}

#[derive(Debug, PartialEq, Eq)]
pub struct StorageWriteRequest {
    pub address: StarkFelt,
    pub value: StarkFelt,
}

pub const STORAGE_WRITE_REQUEST_SIZE: usize = 2;

impl StorageWriteRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let address = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        let value = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 1))?)?;
        Ok(SyscallRequest::StorageWrite(StorageWriteRequest { address, value }))
    }

    pub fn execute(&self, _syscall_handler: &SyscallHandler) -> ExecutionResult {
        // TODO(AlonH, 21/12/2022): Perform state write.
        assert_eq!(self.value, StarkFelt::try_from(18).unwrap());
        Ok(SyscallResponse::Write(EmptyResponse {}))
    }
}

pub const STORAGE_WRITE_RESPONSE_SIZE: usize = 0;

pub type StorageWriteResponse = EmptyResponse;

pub struct StorageWrite {
    pub request: StorageWriteRequest,
    pub response: StorageWriteResponse,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SyscallRequest {
    StorageRead(StorageReadRequest),
    StorageWrite(StorageWriteRequest),
}

impl SyscallRequest {
    pub fn read(selector: StarkFelt, vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let selector_bytes: [u8; 32] = selector.bytes().try_into().unwrap();
        match selector_bytes {
            STORAGE_READ_SELECTOR_BYTES => StorageReadRequest::read(vm, ptr),
            STORAGE_WRITE_SELECTOR_BYTES => StorageWriteRequest::read(vm, ptr),
            bytes => Err(SyscallExecutionError::InvalidSyscallSelector(bytes).into()),
        }
    }

    pub fn execute(&self, syscall_handler: &SyscallHandler) -> ExecutionResult {
        match self {
            SyscallRequest::StorageRead(request) => request.execute(syscall_handler),
            SyscallRequest::StorageWrite(request) => request.execute(syscall_handler),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            SyscallRequest::StorageRead(_) => STORAGE_READ_REQUEST_SIZE,
            SyscallRequest::StorageWrite(_) => STORAGE_WRITE_REQUEST_SIZE,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SyscallResponse {
    Read(StorageReadResponse),
    Write(EmptyResponse),
}

impl SyscallResponse {
    pub fn write(&self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        match self {
            SyscallResponse::Read(response) => response.write(vm, ptr),
            SyscallResponse::Write(response) => response.write(vm, ptr),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            SyscallResponse::Read(_) => STORAGE_READ_RESPONSE_SIZE,
            SyscallResponse::Write(_) => STORAGE_WRITE_RESPONSE_SIZE,
        }
    }
}
