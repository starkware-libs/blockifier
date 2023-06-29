use ark_secp256k1 as secp256k1;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::vm_core::VirtualMachine;
use num_bigint::BigUint;
use num_traits::Zero;
use starknet_api::hash::StarkFelt;

use crate::execution::execution_utils::{u256_from_ptr, write_maybe_relocatable};
use crate::execution::syscalls::hint_processor::{SyscallHintProcessor, INVALID_ARGUMENT};
use crate::execution::syscalls::{
    SyscallExecutionError, SyscallRequest, SyscallResponse, SyscallResult, WriteResponseResult,
};

// Secp256k1 new syscall.

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
    // The syscall returns `Option<Secp256k1Point>` which is represented as two felts in Cairo0.
    // The first felt is a indicates if it is `Some` (0) or `None` (1).
    // The second felt is only valid if the first felt is `Some` and contains the ID of the point.
    // The ID of the point is the index of the point in the `secp256k1_points` vector.
    pub optional_ec_point_id: Option<usize>,
}

impl SyscallResponse for Secp256k1NewResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        match self.optional_ec_point_id {
            Some(id) => {
                // Cairo 1 representation of Some(id).
                write_maybe_relocatable(vm, ptr, 0)?;
                write_maybe_relocatable(vm, ptr, id)?;
            }
            None => {
                // Cairo 1 representation of None.
                write_maybe_relocatable(vm, ptr, 1)?;
                write_maybe_relocatable(vm, ptr, 0)?;
            }
        };
        Ok(())
    }
}

pub fn secp256k1_new(
    request: Secp256k1NewRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<Secp256k1NewResponse> {
    let modulos = <secp256k1::Fq as ark_ff::PrimeField>::MODULUS.into();
    let (x, y) = (request.x, request.y);
    if x >= modulos || y >= modulos {
        return Err(SyscallExecutionError::SyscallError {
            error_data: vec![
                StarkFelt::try_from(INVALID_ARGUMENT).map_err(SyscallExecutionError::from)?,
            ],
        });
    }
    let p = if x.is_zero() && y.is_zero() {
        secp256k1::Affine::identity()
    } else {
        secp256k1::Affine::new_unchecked(x.into(), y.into())
    };
    let optional_ec_point_id = if p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve() {
        let points = &mut syscall_handler.secp256k1_points;
        let id = points.len();
        points.push(p);
        Some(id)
    } else {
        None
    };
    Ok(Secp256k1NewResponse { optional_ec_point_id })
}
