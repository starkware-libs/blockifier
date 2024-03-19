use ark_ec::short_weierstrass;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::{BigInteger, PrimeField};
use cairo_felt::Felt252;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::vm_core::VirtualMachine;
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use starknet_api::hash::StarkFelt;

use crate::abi::sierra_types::{SierraType, SierraU256};
use crate::execution::execution_utils::{
    felt_from_ptr, stark_felt_from_ptr, write_maybe_relocatable, write_u256,
};
use crate::execution::syscalls::hint_processor::{
    felt_to_bool, SyscallHintProcessor, INVALID_ARGUMENT,
};
use crate::execution::syscalls::{
    felt_to_stark_felt, SyscallExecutionError, SyscallRequest, SyscallResponse, SyscallResult,
    WriteResponseResult,
};

#[derive(Debug, Default, Eq, PartialEq)]
pub struct SecpHintProcessor<Curve: SWCurveConfig> {
    points: Vec<short_weierstrass::Affine<Curve>>,
}

impl<Curve: SWCurveConfig> SecpHintProcessor<Curve>
where
    Curve::BaseField: PrimeField,
{
    pub fn secp_add(&mut self, request: SecpAddRequest) -> SyscallResult<SecpAddResponse> {
        let lhs = self.get_point_by_id(request.lhs_id)?;
        let rhs = self.get_point_by_id(request.rhs_id)?;
        let result = *lhs + *rhs;
        let ec_point_id = self.allocate_point(result.into());
        Ok(SecpOpRespone { ec_point_id })
    }

    pub fn secp_mul(&mut self, request: SecpMulRequest) -> SyscallResult<SecpMulResponse> {
        let ep_point = self.get_point_by_id(request.ec_point_id)?;
        let result = *ep_point * Curve::ScalarField::from(request.multiplier);
        let ec_point_id = self.allocate_point(result.into());
        Ok(SecpOpRespone { ec_point_id })
    }

    pub fn secp_get_point_from_x(
        &mut self,
        request: SecpGetPointFromXRequest,
    ) -> SyscallResult<SecpGetPointFromXResponse> {
        let modulos = Curve::BaseField::MODULUS.into();

        if request.x >= modulos {
            return Err(SyscallExecutionError::SyscallError {
                error_data: vec![
                    StarkFelt::try_from(INVALID_ARGUMENT).map_err(SyscallExecutionError::from)?,
                ],
            });
        }

        let x = request.x.into();
        let maybe_ec_point = short_weierstrass::Affine::<Curve>::get_ys_from_x_unchecked(x)
            .map(|(smaller, greater)| {
                // Return the correct y coordinate based on the parity.
                if smaller.into_bigint().is_odd() == request.y_parity { smaller } else { greater }
            })
            .map(|y| short_weierstrass::Affine::<Curve>::new_unchecked(x, y))
            .filter(|p| p.is_in_correct_subgroup_assuming_on_curve());

        Ok(SecpGetPointFromXResponse {
            optional_ec_point_id: maybe_ec_point.map(|ec_point| self.allocate_point(ec_point)),
        })
    }

    pub fn secp_get_xy(&mut self, request: SecpGetXyRequest) -> SyscallResult<SecpGetXyResponse> {
        let ec_point = self.get_point_by_id(request.ec_point_id)?;

        Ok(SecpGetXyResponse { x: ec_point.x.into(), y: ec_point.y.into() })
    }

    pub fn secp_new(&mut self, request: SecpNewRequest) -> SyscallResult<SecpNewResponse> {
        let ec_point = self.secp_new_unchecked(request)?;
        let ec_point_id = ec_point.optional_ec_point_id.unwrap();
        let ec_point = self.get_point_by_id(Felt252::from(ec_point_id))?;

        let optional_ec_point_id =
            if ec_point.is_on_curve() && ec_point.is_in_correct_subgroup_assuming_on_curve() {
                Some(ec_point_id)
            } else {
                None
            };
        Ok(SecpNewResponse { optional_ec_point_id })
    }

    pub fn secp_new_unchecked(
        &mut self,
        request: SecpNewRequest,
    ) -> SyscallResult<SecpNewResponse> {
        let modulos = Curve::BaseField::MODULUS.into();
        let (x, y) = (request.x, request.y);
        if x >= modulos || y >= modulos {
            return Err(SyscallExecutionError::SyscallError {
                error_data: vec![
                    StarkFelt::try_from(INVALID_ARGUMENT).map_err(SyscallExecutionError::from)?,
                ],
            });
        }
        let ec_point = if x.is_zero() && y.is_zero() {
            short_weierstrass::Affine::<Curve>::identity()
        } else {
            short_weierstrass::Affine::<Curve>::new_unchecked(x.into(), y.into())
        };
        Ok(SecpNewResponse { optional_ec_point_id: Some(self.allocate_point(ec_point)) })
    }

    pub fn allocate_point(&mut self, ec_point: short_weierstrass::Affine<Curve>) -> usize {
        let points = &mut self.points;
        let id = points.len();
        points.push(ec_point);
        id
    }

    pub fn get_point_by_id(
        &self,
        ec_point_id: Felt252,
    ) -> SyscallResult<&short_weierstrass::Affine<Curve>> {
        ec_point_id.to_usize().and_then(|id| self.points.get(id)).ok_or_else(|| {
            SyscallExecutionError::InvalidSyscallInput {
                input: felt_to_stark_felt(&ec_point_id),
                info: "Invalid Secp point ID".to_string(),
            }
        })
    }
}

// The x and y coordinates of an elliptic curve point.
#[derive(Debug, Eq, PartialEq)]
pub struct EcPointCoordinates {
    pub x: BigUint,
    pub y: BigUint,
}

#[derive(Debug, Eq, PartialEq)]
pub struct SecpOpRespone {
    pub ec_point_id: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub struct SecpOptionalEcPointResponse {
    // `Option<SecpPoint>` which is represented as two felts.
    // The first felt is a indicates if it is `Some` (0) or `None` (1).
    // The second felt is only valid if the first felt is `Some` and contains the ID of the point.
    // The ID allocated by the Secp hint processor.
    pub optional_ec_point_id: Option<usize>,
}

impl SyscallResponse for SecpOptionalEcPointResponse {
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

impl SyscallResponse for SecpOpRespone {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_maybe_relocatable(vm, ptr, self.ec_point_id)?;
        Ok(())
    }
}

// SecpAdd syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct SecpAddRequest {
    pub lhs_id: Felt252,
    pub rhs_id: Felt252,
}

impl SyscallRequest for SecpAddRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<SecpAddRequest> {
        Ok(SecpAddRequest { lhs_id: felt_from_ptr(vm, ptr)?, rhs_id: felt_from_ptr(vm, ptr)? })
    }
}

pub type SecpAddResponse = SecpOpRespone;

pub fn secp256k1_add(
    request: SecpAddRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<SecpOpRespone> {
    syscall_handler.secp256k1_hint_processor.secp_add(request)
}

pub fn secp256r1_add(
    request: SecpAddRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<SecpOpRespone> {
    syscall_handler.secp256r1_hint_processor.secp_add(request)
}

// SecpGetPointFromXRequest syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct SecpGetPointFromXRequest {
    pub x: BigUint,
    // The parity of the y coordinate, assuming a point with the given x coordinate exists.
    // True means the y coordinate is odd.
    pub y_parity: bool,
}

impl SyscallRequest for SecpGetPointFromXRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<SecpGetPointFromXRequest> {
        let x = SierraU256::from_memory(vm, ptr)?.to_biguint();

        let y_parity = felt_to_bool(stark_felt_from_ptr(vm, ptr)?, "Invalid y parity")?;
        Ok(SecpGetPointFromXRequest { x, y_parity })
    }
}

pub type SecpGetPointFromXResponse = SecpOptionalEcPointResponse;

pub fn secp256k1_get_point_from_x(
    request: SecpGetPointFromXRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<SecpGetPointFromXResponse> {
    syscall_handler.secp256k1_hint_processor.secp_get_point_from_x(request)
}

pub fn secp256r1_get_point_from_x(
    request: SecpGetPointFromXRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<SecpGetPointFromXResponse> {
    syscall_handler.secp256r1_hint_processor.secp_get_point_from_x(request)
}

// SecpGetXy syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct SecpGetXyRequest {
    pub ec_point_id: Felt252,
}

impl SyscallRequest for SecpGetXyRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<SecpGetXyRequest> {
        Ok(SecpGetXyRequest { ec_point_id: felt_from_ptr(vm, ptr)? })
    }
}

pub type SecpGetXyResponse = EcPointCoordinates;

impl SyscallResponse for SecpGetXyResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_u256(vm, ptr, self.x)?;
        write_u256(vm, ptr, self.y)?;
        Ok(())
    }
}

pub fn secp256k1_get_xy(
    request: SecpGetXyRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<SecpGetXyResponse> {
    syscall_handler.secp256k1_hint_processor.secp_get_xy(request)
}

pub fn secp256r1_get_xy(
    request: SecpGetXyRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<SecpGetXyResponse> {
    syscall_handler.secp256r1_hint_processor.secp_get_xy(request)
}

// SecpMul syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct SecpMulRequest {
    pub ec_point_id: Felt252,
    pub multiplier: BigUint,
}

impl SyscallRequest for SecpMulRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<SecpMulRequest> {
        let ec_point_id = felt_from_ptr(vm, ptr)?;
        let multiplier = SierraU256::from_memory(vm, ptr)?.to_biguint();
        Ok(SecpMulRequest { ec_point_id, multiplier })
    }
}

pub type SecpMulResponse = SecpOpRespone;

pub fn secp256k1_mul(
    request: SecpMulRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<SecpMulResponse> {
    syscall_handler.secp256k1_hint_processor.secp_mul(request)
}

pub fn secp256r1_mul(
    request: SecpMulRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<SecpMulResponse> {
    syscall_handler.secp256r1_hint_processor.secp_mul(request)
}

// SecpNew syscall.

pub type SecpNewRequest = EcPointCoordinates;

impl SyscallRequest for SecpNewRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<SecpNewRequest> {
        let x = SierraU256::from_memory(vm, ptr)?.to_biguint();
        let y = SierraU256::from_memory(vm, ptr)?.to_biguint();
        Ok(SecpNewRequest { x, y })
    }
}

pub type SecpNewResponse = SecpOptionalEcPointResponse;

pub fn secp256k1_new(
    request: SecpNewRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<SecpNewResponse> {
    syscall_handler.secp256k1_hint_processor.secp_new(request)
}

pub type Secp256r1NewRequest = EcPointCoordinates;
pub type Secp256r1NewResponse = SecpOptionalEcPointResponse;

pub fn secp256r1_new(
    request: Secp256r1NewRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<Secp256r1NewResponse> {
    syscall_handler.secp256r1_hint_processor.secp_new(request)
}
