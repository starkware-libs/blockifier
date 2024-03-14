use std::iter::once;

use cairo_native::starknet::{Secp256k1Point, U256};
use k256::elliptic_curve::generic_array::GenericArray;
use k256::elliptic_curve::sec1::{Coordinates, FromEncodedPoint, ToEncodedPoint};
use starknet_types_core::felt::Felt;

use crate::execution::secp_shared::PointError;
use crate::execution::syscalls::hint_processor::{INVALID_POINT, UNREACHABLE_ERROR};

#[derive(Debug, Clone, Default)]
pub struct K1Point {
    pub point: k256::ProjectivePoint,
}

impl K1Point {
    pub fn new(point: k256::ProjectivePoint) -> Self {
        Self { point }
    }
}

impl From<PointError> for Vec<Felt> {
    fn from(e: PointError) -> Self {
        vec![match e {
            PointError::InvalidPoint => Felt::from_hex(INVALID_POINT).unwrap(),
            PointError::UnreachableError => Felt::from_hex(UNREACHABLE_ERROR).unwrap(),
        }]
    }
}

impl TryFrom<Secp256k1Point> for K1Point {
    type Error = PointError;

    fn try_from(value: Secp256k1Point) -> Result<Self, Self::Error> {
        let x = value.x;
        let y = value.y;

        Self::try_from((x, y))
    }
}

impl TryFrom<(U256, U256)> for K1Point {
    type Error = PointError;

    fn try_from(value: (U256, U256)) -> Result<Self, Self::Error> {
        let (x, y) = value;

        let point = k256::ProjectivePoint::from_encoded_point(
            &k256::EncodedPoint::from_affine_coordinates(
                &GenericArray::from_exact_iter(
                    x.hi.to_be_bytes().into_iter().chain(x.lo.to_be_bytes()),
                )
                .ok_or(PointError::InvalidPoint)?,
                &GenericArray::from_exact_iter(
                    y.hi.to_be_bytes().into_iter().chain(y.lo.to_be_bytes()),
                )
                .ok_or(PointError::InvalidPoint)?,
                false,
            ),
        );

        if bool::from(point.is_some()) {
            Ok(Self { point: point.unwrap() })
        } else {
            Err(PointError::InvalidPoint)
        }
    }
}

impl TryInto<Secp256k1Point> for K1Point {
    type Error = PointError;

    fn try_into(self) -> Result<Secp256k1Point, Self::Error> {
        let p = self.point.to_encoded_point(false);
        let (x, y) = match p.coordinates() {
            Coordinates::Uncompressed { x, y } => (x, y),
            _ => {
                return Err(PointError::UnreachableError);
            }
        };

        let x: [u8; 32] = x.as_slice().try_into().map_err(|_| PointError::UnreachableError)?;
        let y: [u8; 32] = y.as_slice().try_into().map_err(|_| PointError::UnreachableError)?;

        Ok(Secp256k1Point {
            x: U256 {
                hi: u128::from_be_bytes(
                    x[0..16].try_into().map_err(|_| PointError::UnreachableError)?,
                ),
                lo: u128::from_be_bytes(
                    x[16..32].try_into().map_err(|_| PointError::UnreachableError)?,
                ),
            },
            y: U256 {
                hi: u128::from_be_bytes(
                    y[0..16].try_into().map_err(|_| PointError::UnreachableError)?,
                ),
                lo: u128::from_be_bytes(
                    y[16..32].try_into().map_err(|_| PointError::UnreachableError)?,
                ),
            },
        })
    }
}

impl TryFrom<(U256, bool)> for K1Point {
    type Error = PointError;

    fn try_from((x, y_parity): (U256, bool)) -> Result<Self, Self::Error> {
        let point = k256::ProjectivePoint::from_encoded_point(
            &k256::EncodedPoint::from_bytes(
                k256::CompressedPoint::from_exact_iter(
                    once(0x02 | y_parity as u8).chain(x.hi.to_be_bytes()).chain(x.lo.to_be_bytes()),
                )
                .ok_or(PointError::InvalidPoint)?,
            )
            .map_err(|_| PointError::InvalidPoint)?,
        );

        if bool::from(point.is_some()) {
            Ok(Self { point: point.unwrap() })
        } else {
            Err(PointError::InvalidPoint)
        }
    }
}
