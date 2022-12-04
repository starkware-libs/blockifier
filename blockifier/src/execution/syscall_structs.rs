use std::collections::HashMap;

use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::vm_core::VirtualMachine;
use starknet_api::StarkHash;

use super::syscall_handling::SyscallHandler;
use crate::execution::entry_point::EntryPointResult;

pub type ReadRequestResult = EntryPointResult<Box<dyn SyscallRequest>>;
pub type ExecutionResult = EntryPointResult<Box<dyn SyscallResponse>>;
pub type WriteResponseResult = EntryPointResult<()>;

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
    HashMap::<StarkHash, SyscallInfo>::new()
}
