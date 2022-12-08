use std::mem;

use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::vm_core::VirtualMachine;
use starknet_api::hash::StarkFelt;

use crate::execution::cairo_run_utils::{felt_to_bigint, get_felt_from_memory_cell};
use crate::execution::entry_point::EntryPointResult;
use crate::execution::errors::SyscallExecutionError;
use crate::execution::syscall_handling::SyscallHandler;

pub type ReadRequestResult = EntryPointResult<SyscallRequest>;
pub type ExecutionResult = EntryPointResult<SyscallResponse>;
pub type WriteResponseResult = EntryPointResult<()>;

const STORAGE_READ_SELECTOR_BYTES: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 116, 111, 114, 97, 103, 101,
    82, 101, 97, 100,
];
const STORAGE_WRITE_SELECTOR_BYTES: [u8; 32] = [
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

#[derive(Debug, PartialEq, Eq)]
pub struct StorageReadRequest {
    pub selector: StarkFelt,
    pub address: StarkFelt,
}

impl StorageReadRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let selector = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        let address = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 1))?)?;
        Ok(SyscallRequest::Read(StorageReadRequest { selector, address }))
    }

    pub fn execute(&self, _syscall_handler: &SyscallHandler) -> ExecutionResult {
        // TODO(AlonH, 21/12/2022): Perform state read.
        let value = StarkFelt::from(17);
        Ok(SyscallResponse::Read(StorageReadResponse { value }))
    }
}

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
    pub selector: StarkFelt,
    pub address: StarkFelt,
    pub value: StarkFelt,
}

impl StorageWriteRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let selector = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        let address = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 1))?)?;
        let value = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 2))?)?;
        Ok(SyscallRequest::Write(StorageWriteRequest { selector, address, value }))
    }

    pub fn execute(&self, _syscall_handler: &SyscallHandler) -> ExecutionResult {
        // TODO(AlonH, 21/12/2022): Perform state write.
        assert_eq!(self.value, StarkFelt::try_from(18).unwrap());
        Ok(SyscallResponse::Write(EmptyResponse {}))
    }
}

pub struct StorageWrite {
    pub request: StorageWriteRequest,
    pub response: EmptyResponse,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SyscallSelector {
    Read,
    Write,
}

impl SyscallSelector {
    pub fn parse_selector(selector: StarkFelt) -> EntryPointResult<Self> {
        let selector_bytes: [u8; 32] = selector.bytes().try_into().unwrap();
        match selector_bytes {
            STORAGE_READ_SELECTOR_BYTES => Ok(Self::Read),
            STORAGE_WRITE_SELECTOR_BYTES => Ok(Self::Write),
            bytes => Err(SyscallExecutionError::InvalidSyscallSelector(bytes).into()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SyscallRequest {
    Read(StorageReadRequest),
    Write(StorageWriteRequest),
}

impl SyscallRequest {
    pub fn read(
        selector: SyscallSelector,
        vm: &VirtualMachine,
        ptr: &Relocatable,
    ) -> ReadRequestResult {
        match selector {
            SyscallSelector::Read => StorageReadRequest::read(vm, ptr),
            SyscallSelector::Write => StorageWriteRequest::read(vm, ptr),
        }
    }

    pub fn execute(&self, syscall_handler: &SyscallHandler) -> ExecutionResult {
        match self {
            SyscallRequest::Read(request) => request.execute(syscall_handler),
            SyscallRequest::Write(request) => request.execute(syscall_handler),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            SyscallRequest::Read(_) => size_in_felts::<StorageReadRequest>(),
            SyscallRequest::Write(_) => size_in_felts::<StorageWriteRequest>(),
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
            SyscallResponse::Read(_) => size_in_felts::<StorageReadResponse>(),
            SyscallResponse::Write(_) => size_in_felts::<EmptyResponse>(),
        }
    }
}

pub fn size_in_felts<T>() -> usize {
    mem::size_of::<T>() / mem::size_of::<StarkFelt>()
}
