use std::convert::TryFrom;

use num_bigint::BigUint;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;

use crate::errors::NativeBlockifierResult;

#[derive(Eq, FromPyObject, Hash, PartialEq, Clone, Copy)]
pub struct PyFelt(#[pyo3(from_py_with = "pyint_to_stark_felt")] pub StarkFelt);

impl IntoPy<PyObject> for PyFelt {
    fn into_py(self, py: Python<'_>) -> PyObject {
        BigUint::from_bytes_be(self.0.bytes()).into_py(py)
    }
}

impl From<ContractAddress> for PyFelt {
    fn from(address: ContractAddress) -> Self {
        Self(*address.0.key())
    }
}

fn pyint_to_stark_felt(int: &PyAny) -> PyResult<StarkFelt> {
    let biguint: BigUint = int.extract()?;
    biguint_to_felt(biguint).map_err(|e| PyValueError::new_err(e.to_string()))
}

// TODO: Convert to a `TryFrom` cast and put in starknet-api (In StarkFelt).
pub fn biguint_to_felt(biguint: BigUint) -> NativeBlockifierResult<StarkFelt> {
    let biguint_hex = format!("{biguint:#x}");
    Ok(StarkFelt::try_from(&*biguint_hex)?)
}
