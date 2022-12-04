use std::collections::HashMap;

use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::vm_core::VirtualMachine;
use starknet_api::StarkHash;

pub type SyscallResult<T> = Result<T, VirtualMachineError>;
pub type ReadResult = SyscallResult<Box<dyn SyscallRequest>>;
pub type ExecuteResult = SyscallResult<Box<dyn SyscallResponse>>;
pub type WriteResult = SyscallResult<()>;

/// Trait to be implemented by all syscall requests structs.
pub trait SyscallRequest {
    fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadResult
    where
        Self: Sized;

    fn execute(&self) -> ExecuteResult;
}

/// Trait to be implemented by all syscall response structs.
pub trait SyscallResponse {
    fn write(&self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResult;
}

pub type SyscallRequestFactory = dyn Fn(&VirtualMachine, &Relocatable) -> ReadResult;

pub struct SyscallInfo {
    pub syscall_request_factory: Box<SyscallRequestFactory>,
    pub syscall_request_size: usize,
    pub syscall_response_size: usize,
}

// TODO(AlonH, 21/12/2022): Define and use a syscall selector enum instead of `StarkHash`.
pub fn get_syscall_info() -> HashMap<StarkHash, SyscallInfo> {
    HashMap::<StarkHash, SyscallInfo>::new()
}
