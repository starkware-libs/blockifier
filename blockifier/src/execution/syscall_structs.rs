use std::collections::HashMap;

use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::vm_core::VirtualMachine;
use starknet_api::StarkHash;

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
    HashMap::<StarkHash, SysCallInfo>::new()
}
