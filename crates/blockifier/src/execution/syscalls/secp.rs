use ark_ff::BigInteger;
use ark_secp256k1 as secp256k1;
use cairo_felt::Felt252;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::vm_core::VirtualMachine;
use num_bigint::BigUint;
use num_traits::Zero;
use starknet_api::hash::StarkFelt;

use crate::execution::execution_utils::{
    felt_from_ptr, stark_felt_from_ptr, u256_from_ptr, write_maybe_relocatable, write_u256,
};
use crate::execution::syscalls::hint_processor::{
    felt_to_bool, SyscallHintProcessor, INVALID_ARGUMENT,
};
use crate::execution::syscalls::{
    SyscallExecutionError, SyscallRequest, SyscallResponse, SyscallResult, WriteResponseResult,
};

// The x and y coordinates of an elliptic curve point.
#[derive(Debug, Eq, PartialEq)]
pub struct EcPointCoordinates {
    pub x: BigUint,
    pub y: BigUint,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Secp256k1OpRespone {
    pub ec_point_id: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Secp256k1OptionalEcPointResponse {
    // `Option<Secp256k1Point>` which is represented as two felts.
    // The first felt is a indicates if it is `Some` (0) or `None` (1).
    // The second felt is only valid if the first felt is `Some` and contains the ID of the point.
    // The ID of the point is the index of the point in the `secp256k1_points` vector.
    pub optional_ec_point_id: Option<usize>,
}

impl SyscallResponse for Secp256k1OptionalEcPointResponse {
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

impl SyscallResponse for Secp256k1OpRespone {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_maybe_relocatable(vm, ptr, self.ec_point_id)?;
        Ok(())
    }
}

// Secp256k1Add syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct Secp256k1AddRequest {
    pub lhs_id: Felt252,
    pub rhs_id: Felt252,
}

impl SyscallRequest for Secp256k1AddRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Secp256k1AddRequest> {
        Ok(Secp256k1AddRequest { lhs_id: felt_from_ptr(vm, ptr)?, rhs_id: felt_from_ptr(vm, ptr)? })
    }
}

type Secp256k1AddResponse = Secp256k1OpRespone;

pub fn secp256k1_add(
    request: Secp256k1AddRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<Secp256k1AddResponse> {
    let lhs = syscall_handler.get_secp256k1_point_by_id(request.lhs_id)?;
    let rhs = syscall_handler.get_secp256k1_point_by_id(request.rhs_id)?;
    let result = *lhs + *rhs;
    let ec_point_id = syscall_handler.allocate_secp256k1_point(result.into());
    Ok(Secp256k1OpRespone { ec_point_id })
}

// Secp256k1GetPointFromXRequest syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct Secp256k1GetPointFromXRequest {
    x: BigUint,
    // The parity of the y coordinate, assuming a point with the given x coordinate exists.
    // True means the y coordinate is odd.
    y_parity: bool,
}

impl SyscallRequest for Secp256k1GetPointFromXRequest {
    fn read(
        vm: &VirtualMachine,
        ptr: &mut Relocatable,
    ) -> SyscallResult<Secp256k1GetPointFromXRequest> {
        let x = u256_from_ptr(vm, ptr)?;

        let y_parity = felt_to_bool(stark_felt_from_ptr(vm, ptr)?, "Invalid y parity")?;
        Ok(Secp256k1GetPointFromXRequest { x, y_parity })
    }
}

type Secp256k1GetPointFromXResponse = Secp256k1OptionalEcPointResponse;

pub fn secp256k1_get_point_from_x(
    request: Secp256k1GetPointFromXRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<Secp256k1GetPointFromXResponse> {
    let modulos = <secp256k1::Fq as ark_ff::PrimeField>::MODULUS.into();

    if request.x >= modulos {
        return Err(SyscallExecutionError::SyscallError {
            error_data: vec![
                StarkFelt::try_from(INVALID_ARGUMENT).map_err(SyscallExecutionError::from)?,
            ],
        });
    }

    let x = request.x.into();
    let maybe_ec_point = secp256k1::Affine::get_ys_from_x_unchecked(x)
        .map(|(smaller, greater)| {
            // Return the correct y coordinate based on the parity.
            if smaller.0.is_odd() == request.y_parity { smaller } else { greater }
        })
        .map(|y| secp256k1::Affine::new_unchecked(x, y))
        .filter(|p| p.is_in_correct_subgroup_assuming_on_curve());

    Ok(Secp256k1GetPointFromXResponse {
        optional_ec_point_id: maybe_ec_point
            .map(|ec_point| syscall_handler.allocate_secp256k1_point(ec_point)),
    })
}

// Secp256k1GetXy syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct Secp256k1GetXyRequest {
    pub ec_point_id: Felt252,
}

impl SyscallRequest for Secp256k1GetXyRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Secp256k1GetXyRequest> {
        Ok(Secp256k1GetXyRequest { ec_point_id: felt_from_ptr(vm, ptr)? })
    }
}

type Secp256k1GetXyResponse = EcPointCoordinates;

impl SyscallResponse for Secp256k1GetXyResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_u256(vm, ptr, self.x)?;
        write_u256(vm, ptr, self.y)?;
        Ok(())
    }
}

pub fn secp256k1_get_xy(
    request: Secp256k1GetXyRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<Secp256k1GetXyResponse> {
    let ec_point = syscall_handler.get_secp256k1_point_by_id(request.ec_point_id)?;

    Ok(Secp256k1GetXyResponse { x: ec_point.x.into(), y: ec_point.y.into() })
}

// Secp256k1Mul syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct Secp256k1MulRequest {
    pub ec_point_id: Felt252,
    pub multiplier: BigUint,
}

impl SyscallRequest for Secp256k1MulRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Secp256k1MulRequest> {
        let ec_point_id = felt_from_ptr(vm, ptr)?;
        let multiplier = u256_from_ptr(vm, ptr)?;
        Ok(Secp256k1MulRequest { ec_point_id, multiplier })
    }
}

type Secp256k1MulResponse = Secp256k1OpRespone;

pub fn secp256k1_mul(
    request: Secp256k1MulRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<Secp256k1MulResponse> {
    let ep_point = syscall_handler.get_secp256k1_point_by_id(request.ec_point_id)?;
    let result = *ep_point * secp256k1::Fr::from(request.multiplier);
    let ec_point_id = syscall_handler.allocate_secp256k1_point(result.into());
    Ok(Secp256k1OpRespone { ec_point_id })
}

// Secp256k1New syscall.

type Secp256k1NewRequest = EcPointCoordinates;

impl SyscallRequest for Secp256k1NewRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Secp256k1NewRequest> {
        let x = u256_from_ptr(vm, ptr)?;
        let y = u256_from_ptr(vm, ptr)?;
        Ok(Secp256k1NewRequest { x, y })
    }
}

type Secp256k1NewResponse = Secp256k1OptionalEcPointResponse;

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
    let ec_point = if x.is_zero() && y.is_zero() {
        secp256k1::Affine::identity()
    } else {
        secp256k1::Affine::new_unchecked(x.into(), y.into())
    };
    let optional_ec_point_id =
        if ec_point.is_on_curve() && ec_point.is_in_correct_subgroup_assuming_on_curve() {
            Some(syscall_handler.allocate_secp256k1_point(ec_point))
        } else {
            None
        };
    Ok(Secp256k1NewResponse { optional_ec_point_id })
}
