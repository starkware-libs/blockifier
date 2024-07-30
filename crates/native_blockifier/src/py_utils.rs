use blockifier::blockifier::block::BlockNumberHashPair;
use num_bigint::BigUint;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use starknet_api::core::{ChainId, ClassHash, CompiledClassHash, ContractAddress, EthAddress};
use starknet_api::state::StorageKey;
use starknet_types_core::felt::Felt;

use crate::errors::{NativeBlockifierInputError, NativeBlockifierResult};

#[derive(Clone, Copy, Debug, Default, Eq, FromPyObject, Hash, PartialEq)]
pub struct PyFelt(#[pyo3(from_py_with = "int_to_stark_felt")] pub Felt);

impl IntoPy<PyObject> for PyFelt {
    fn into_py(self, py: Python<'_>) -> PyObject {
        BigUint::from_bytes_be(self.0.to_bytes_be().as_slice()).into_py(py)
    }
}

impl From<u64> for PyFelt {
    fn from(value: u64) -> Self {
        Self(Felt::from(value))
    }
}

impl From<u8> for PyFelt {
    fn from(value: u8) -> Self {
        Self(Felt::from(value))
    }
}

impl From<ContractAddress> for PyFelt {
    fn from(address: ContractAddress) -> Self {
        Self(*address.0.key())
    }
}

impl From<EthAddress> for PyFelt {
    fn from(address: EthAddress) -> Self {
        let address_as_bytes: [u8; 20] = address.0.to_fixed_bytes();
        // Pad with 12 zeros.
        let mut bytes = [0; 32];
        bytes[12..32].copy_from_slice(&address_as_bytes);
        PyFelt(Felt::from_bytes_be(&bytes))
    }
}

impl From<ClassHash> for PyFelt {
    fn from(class_hash: ClassHash) -> Self {
        Self(class_hash.0)
    }
}

impl From<CompiledClassHash> for PyFelt {
    fn from(compiled_class_hash: CompiledClassHash) -> Self {
        Self(compiled_class_hash.0)
    }
}

impl From<StorageKey> for PyFelt {
    fn from(value: StorageKey) -> Self {
        Self(*value.0.key())
    }
}

fn int_to_stark_felt(int: &PyAny) -> PyResult<Felt> {
    let biguint: BigUint = int.extract()?;
    biguint_to_felt(biguint).map_err(|e| PyValueError::new_err(e.to_string()))
}

// TODO: Convert to a `TryFrom` cast and put in starknet-api (In Felt).
pub fn biguint_to_felt(biguint: BigUint) -> NativeBlockifierResult<Felt> {
    let biguint_hex = format!("{biguint:#x}");
    Ok(Felt::from_hex(&biguint_hex).map_err(NativeBlockifierInputError::from)?)
}

pub fn to_py_vec<T, PyT, F>(values: Vec<T>, converter: F) -> Vec<PyT>
where
    F: FnMut(T) -> PyT,
{
    values.into_iter().map(converter).collect()
}

pub fn from_py_felts(py_felts: Vec<PyFelt>) -> Vec<Felt> {
    py_felts.into_iter().map(|felt| felt.0).collect()
}

pub fn int_to_chain_id(int: &PyAny) -> PyResult<ChainId> {
    let biguint: BigUint = int.extract()?;
    Ok(ChainId::Other(String::from_utf8_lossy(&biguint.to_bytes_be()).into()))
}

pub fn py_attr<T>(obj: &PyAny, attr: &str) -> NativeBlockifierResult<T>
where
    T: for<'a> FromPyObject<'a>,
    T: Clone,
{
    Ok(obj.getattr(attr)?.extract()?)
}

pub fn into_block_number_hash_pair(
    old_block_number_and_hash: Option<(u64, PyFelt)>,
) -> Option<BlockNumberHashPair> {
    old_block_number_and_hash
        .map(|(block_number, block_hash)| BlockNumberHashPair::new(block_number, block_hash.0))
}
