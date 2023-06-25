// Secp256k1 new syscall.

use ark_secp256k1 as secp256k1;
use cairo_felt::Felt252;
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

pub fn secp256k1_new(
    request: Secp256k1NewRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut Felt252,
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
    Ok(Secp256k1NewResponse {
        optional_ec_point_id: if p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve() {
            let points = &mut syscall_handler.secp256k1_points;
            let id = points.len();
            points.push(p);
            Some(id)
        } else {
            None
        },
    })
}
