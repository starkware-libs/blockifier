use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_rs::vm::vm_core::VirtualMachine;
use starknet_api::core::ContractAddress;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::shash;
use starknet_api::state::StorageKey;

use crate::execution::errors::SyscallExecutionError;
use crate::execution::execution_utils::{
    felt_to_bigint, get_felt_from_memory_cell, get_felt_range,
};
use crate::execution::syscall_handling::SyscallHandler;

pub type SyscallResult<T> = Result<T, SyscallExecutionError>;
pub type ReadRequestResult = SyscallResult<SyscallRequest>;
pub type ExecutionResult = SyscallResult<SyscallResponse>;
pub type WriteResponseResult = SyscallResult<()>;

// TODO(AlonH, 21/12/2022): Create using const function.
pub const LIBRARY_CALL_SELECTOR_BYTES: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76, 105, 98, 114, 97, 114, 121,
    67, 97, 108, 108,
];
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
    pub address: StorageKey,
}

impl StorageReadRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let address: StarkFelt = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        let address: StorageKey = address.try_into()?;
        Ok(SyscallRequest::StorageRead(StorageReadRequest { address }))
    }

    pub fn execute(&self, syscall_handler: &mut SyscallHandler) -> ExecutionResult {
        // TODO(AlonH, 21/12/2022): Use actual contract address once it's part of the entry point.
        let contract_address = ContractAddress::try_from(shash!("0x1")).unwrap();
        // TODO(AlonH, 21/12/2022): Remove unwrap once errors are created for state.
        let value = syscall_handler.state.get_storage_at(contract_address, self.address).unwrap();
        Ok(SyscallResponse::StorageRead(StorageReadResponse { value: *value }))
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
        // TODO(AlonH, 21/12/2022): Use actual contract address once it's part of the entry point.
        let contract_address = ContractAddress::try_from(shash!("0x1")).unwrap();
        syscall_handler.state.set_storage_at(contract_address, self.address, self.value);
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
    pub fn write(&self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        vm.insert_value(ptr, felt_to_bigint(self.retdata_size))?;

        // Write response payload to the memory.
        let segment = vm.add_memory_segment();
        vm.insert_value(&(ptr + 1), &segment)?;
        let data: Vec<MaybeRelocatable> =
            self.retdata.iter().map(|x| felt_to_bigint(*x).into()).collect();
        vm.load_data(&segment.into(), data)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct LibraryCallRequest {
    pub class_hash: StarkFelt,
    pub function_selector: StarkFelt,
    pub calldata_size: StarkFelt,
    pub calldata: Vec<StarkFelt>,
}

pub const LIBRARY_CALL_REQUEST_SIZE: usize = 4;

impl LibraryCallRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let class_hash = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        let function_selector = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 1))?)?;
        let calldata_size = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 2))?)?;

        let calldata_ptr = vm.get_maybe(&(ptr + 3))?.unwrap();
        let calldata = get_felt_range(vm, &calldata_ptr, calldata_size.try_into()?)?;

        Ok(SyscallRequest::LibraryCall(LibraryCallRequest {
            class_hash,
            function_selector,
            calldata_size,
            calldata,
        }))
    }

    pub fn execute(&self, _syscall_handler: &mut SyscallHandler) -> ExecutionResult {
        // TODO(AlonH, 21/12/2022): Execute library call.
        Ok(SyscallResponse::LibraryCall(LibraryCallResponse {
            retdata_size: shash!(2),
            retdata: vec![shash!(45), shash!(91)],
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
        let selector_bytes: [u8; 32] = selector.bytes().try_into().unwrap();
        match selector_bytes {
            LIBRARY_CALL_SELECTOR_BYTES => LibraryCallRequest::read(vm, ptr),
            STORAGE_READ_SELECTOR_BYTES => StorageReadRequest::read(vm, ptr),
            STORAGE_WRITE_SELECTOR_BYTES => StorageWriteRequest::read(vm, ptr),
            bytes => Err(SyscallExecutionError::InvalidSyscallSelector(bytes)),
        }
    }

    pub fn execute(&self, syscall_handler: &mut SyscallHandler) -> ExecutionResult {
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
    pub fn write(&self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
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
