use std::collections::HashMap;
use std::mem;

use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::vm_core::VirtualMachine;
use starknet_api::{StarkFelt, StarkHash};

use super::cairo_run_utils::felt_to_bigint;
use crate::execution::cairo_run_utils::get_felt_from_memory_cell;

const STORAGE_READ_SELECTOR: &str = "0x53746f7261676552656164";
const STORAGE_WRITE_SELECTOR: &str = "0x53746f726167655772697465";

pub struct StorageReadRequest {
    pub selector: StarkFelt,
    pub address: StarkFelt,
}

impl SysCallRequest for StorageReadRequest {
    fn read_request(
        vm: &VirtualMachine,
        ptr: &Relocatable,
    ) -> Result<Box<dyn SysCallRequest>, VirtualMachineError> {
        let selector = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        let address = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 1))?)?;
        Ok(Box::new(StorageReadRequest { selector, address }))
    }

    fn execute(&self) -> Result<Box<dyn SysCallResponse>, VirtualMachineError> {
        // TODO(AlonH, 21/12/2022): Perform state read.
        let value = StarkFelt::from_u64(17);
        Ok(Box::new(StorageReadResponse { value }))
    }
}

pub struct StorageReadResponse {
    pub value: StarkFelt,
}

impl SysCallResponse for StorageReadResponse {
    fn write_response(
        &self,
        vm: &mut VirtualMachine,
        ptr: &Relocatable,
    ) -> Result<(), VirtualMachineError> {
        vm.insert_value(ptr, felt_to_bigint(self.value))?;
        Ok(())
    }
}

pub struct StorageRead {
    pub request: StorageReadRequest,
    pub response: StorageReadResponse,
}

pub struct StorageWriteRequest {
    pub selector: StarkFelt,
    pub address: StarkFelt,
    pub value: StarkFelt,
}

impl SysCallRequest for StorageWriteRequest {
    fn read_request(
        vm: &VirtualMachine,
        ptr: &Relocatable,
    ) -> Result<Box<dyn SysCallRequest>, VirtualMachineError> {
        let selector = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        let address = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 1))?)?;
        let value = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 2))?)?;
        Ok(Box::new(StorageWriteRequest { selector, address, value }))
    }

    fn execute(&self) -> Result<Box<dyn SysCallResponse>, VirtualMachineError> {
        // TODO(AlonH, 21/12/2022): Perform state write.
        assert_eq!(self.value, StarkFelt::from_u64(18));
        Ok(Box::new(EmptyResponse {}))
    }
}

pub struct StorageWrite {
    pub request: StorageWriteRequest,
    pub response: EmptyResponse,
}

pub struct EmptyResponse {}

impl SysCallResponse for EmptyResponse {
    fn write_response(
        &self,
        _vm: &mut VirtualMachine,
        _ptr: &Relocatable,
    ) -> Result<(), VirtualMachineError> {
        Ok(())
    }
}

pub trait SysCallRequest {
    fn read_request(
        vm: &VirtualMachine,
        ptr: &Relocatable,
    ) -> Result<Box<dyn SysCallRequest>, VirtualMachineError>
    where
        Self: Sized;

    fn execute(&self) -> Result<Box<dyn SysCallResponse>, VirtualMachineError>;
}

pub trait SysCallResponse {
    fn write_response(
        &self,
        vm: &mut VirtualMachine,
        ptr: &Relocatable,
    ) -> Result<(), VirtualMachineError>;
}

pub type SyscallRequestFactory =
    dyn Fn(&VirtualMachine, &Relocatable) -> Result<Box<dyn SysCallRequest>, VirtualMachineError>;

pub struct SysCallInfo {
    pub syscall_request_factory: Box<SyscallRequestFactory>,
    pub syscall_request_size: usize,
    pub syscall_response_size: usize,
}

pub fn get_syscall_info() -> HashMap<StarkHash, SysCallInfo> {
    let selector_error_msg = "Syscall selector should be able to turn into a `StarkHash`.";
    [
        (
            StarkHash::from_hex(STORAGE_READ_SELECTOR).expect(selector_error_msg),
            SysCallInfo {
                syscall_request_factory: Box::new(StorageReadRequest::read_request),
                syscall_request_size: mem::size_of::<StorageReadRequest>()
                    / mem::size_of::<StarkFelt>(),
                syscall_response_size: mem::size_of::<StorageReadResponse>()
                    / mem::size_of::<StarkFelt>(),
            },
        ),
        (
            StarkHash::from_hex(STORAGE_WRITE_SELECTOR).expect(selector_error_msg),
            SysCallInfo {
                syscall_request_factory: Box::new(StorageWriteRequest::read_request),
                syscall_request_size: mem::size_of::<StorageWriteRequest>()
                    / mem::size_of::<StarkFelt>(),
                syscall_response_size: mem::size_of::<EmptyResponse>()
                    / mem::size_of::<StarkFelt>(),
            },
        ),
    ]
    .into_iter()
    .collect()
}
