// Secp256k1 new syscall.

use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::vm_core::VirtualMachine;
use num_bigint::BigUint;

use crate::execution::execution_utils::{u256_from_ptr, write_maybe_relocatable};
use crate::execution::syscalls::{
    SyscallRequest, SyscallResponse, SyscallResult, WriteResponseResult,
};

#[derive(Debug, Eq, PartialEq)]
pub struct Secp256k1NewRequest {
    pub x: BigUint,
    pub y: BigUint,
}

impl SyscallRequest for Secp256k1NewRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Secp256k1NewRequest> {
        let x = u256_from_ptr(vm, ptr)?;
        let y = u256_from_ptr(vm, ptr)?;
        Ok(Secp256k1NewRequest { x, y })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Secp256k1NewResponse {
    // Some(id) if the point is on the curve, None otherwise.
    pub optional_ec_point_id: Option<usize>,
}

impl SyscallResponse for Secp256k1NewResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        // The syscall returns `Option<Secp256k1Point>` which is represented as two felts in Cairo0.
        match self.optional_ec_point_id {
            Some(id) => {
                write_maybe_relocatable(vm, ptr, 0)?;
                write_maybe_relocatable(vm, ptr, id)?;
            }
            None => {
                write_maybe_relocatable(vm, ptr, 1)?;
                write_maybe_relocatable(vm, ptr, 0)?;
            }
        };
        Ok(())
    }
}
