use std::collections::HashMap;
use std::mem;

use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::vm_core::VirtualMachine;
use starknet_api::{StarkFelt, StarkHash};

use crate::execution::cairo_run_utils::{felt_to_bigint, get_felt_from_memory_cell};
use crate::execution::entry_point::EntryPointResult;
use crate::execution::syscall_handling::SyscallHandler;

pub type ReadRequestResult = EntryPointResult<Box<dyn SyscallRequest>>;
pub type ExecutionResult = EntryPointResult<Box<dyn SyscallResponse>>;
pub type WriteResponseResult = EntryPointResult<()>;

const STORAGE_READ_SELECTOR: &str = "0x53746f7261676552656164";

pub struct StorageReadRequest {
    pub selector: StarkFelt,
    pub address: StarkFelt,
}

impl SyscallRequest for StorageReadRequest {
    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let selector = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        let address = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 1))?)?;
        Ok(Box::new(StorageReadRequest { selector, address }))
    }

    fn execute(&self, _syscall_handler: &SyscallHandler) -> ExecutionResult {
        // TODO(AlonH, 21/12/2022): Perform state read.
        let value = StarkFelt::from_u64(17);
        Ok(Box::new(StorageReadResponse { value }))
    }
}

pub struct StorageReadResponse {
    pub value: StarkFelt,
}

impl SyscallResponse for StorageReadResponse {
    fn write(&self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        vm.insert_value(ptr, felt_to_bigint(self.value))?;
        Ok(())
    }
}

pub struct StorageRead {
    pub request: StorageReadRequest,
    pub response: StorageReadResponse,
}

pub trait SyscallRequest {
    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult
    where
        Self: Sized;

    fn execute(&self, syscall_handler: &SyscallHandler) -> ExecutionResult;
}

pub trait SyscallResponse {
    fn write(&self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult;
}

pub type SyscallRequestFactory = dyn Fn(&VirtualMachine, &Relocatable) -> ReadRequestResult;

pub struct SyscallInfo {
    pub syscall_request_factory: Box<SyscallRequestFactory>,
    pub syscall_request_size: usize,
    pub syscall_response_size: usize,
}

// TODO(AlonH, 21/12/2022): Define and use a syscall selector enum instead of `StarkHash`.
pub fn get_syscall_info() -> HashMap<StarkHash, SyscallInfo> {
    let selector_error_msg = "Syscall selector should be able to turn into a `StarkHash`.";
    [(
        StarkHash::from_hex(STORAGE_READ_SELECTOR).expect(selector_error_msg),
        SyscallInfo {
            syscall_request_factory: Box::new(StorageReadRequest::read),
            syscall_request_size: mem::size_of::<StorageReadRequest>()
                / mem::size_of::<StarkFelt>(),
            syscall_response_size: mem::size_of::<StorageReadResponse>()
                / mem::size_of::<StarkFelt>(),
        },
    )]
    .into_iter()
    .collect()
}
