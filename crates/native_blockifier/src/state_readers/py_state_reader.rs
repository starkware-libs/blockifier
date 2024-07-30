use blockifier::execution::contract_class::{ContractClass, ContractClassV0, ContractClassV1};
use blockifier::state::errors::StateError;
use blockifier::state::state_api::{StateReader, StateResult};
use pyo3::{FromPyObject, PyAny, PyErr, PyObject, PyResult, Python};
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::state::StorageKey;
use starknet_types_core::felt::Felt;

use crate::errors::{
    NativeBlockifierError, NativeBlockifierInputError, NativeBlockifierResult,
    UndeclaredClassHashError,
};
use crate::py_utils::PyFelt;

// The value of Python StorageDomain.ON_CHAIN enum.
const ON_CHAIN_STORAGE_DOMAIN: u8 = 0;

pub struct PyStateReader {
    // A reference to an RsStateReaderProxy Python object.
    //
    // This is a reference to memory allocated on Python's heap and can outlive the GIL.
    // Once PyObject is instantiated, the underlying Python object ref count is increased.
    // Once it is dropped, the ref count is decreased the next time the GIL is acquired in pyo3.
    state_reader_proxy: PyObject,
}

impl PyStateReader {
    pub fn new(state_reader_proxy: &PyAny) -> Self {
        Self { state_reader_proxy: PyObject::from(state_reader_proxy) }
    }
}

impl StateReader for PyStateReader {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<Felt> {
        Python::with_gil(|py| -> PyResult<PyFelt> {
            let args = (ON_CHAIN_STORAGE_DOMAIN, PyFelt::from(contract_address), PyFelt::from(key));
            self.state_reader_proxy.as_ref(py).call_method1("get_storage_at", args)?.extract()
        })
        .map(|felt| felt.0)
        .map_err(|err| StateError::StateReadError(err.to_string()))
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        Python::with_gil(|py| -> PyResult<PyFelt> {
            let args = (ON_CHAIN_STORAGE_DOMAIN, PyFelt::from(contract_address));
            self.state_reader_proxy.as_ref(py).call_method1("get_nonce_at", args)?.extract()
        })
        .map(|nonce| Nonce(nonce.0))
        .map_err(|err| StateError::StateReadError(err.to_string()))
    }

    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        Python::with_gil(|py| -> PyResult<PyFelt> {
            let args = (PyFelt::from(contract_address),);
            self.state_reader_proxy.as_ref(py).call_method1("get_class_hash_at", args)?.extract()
        })
        .map(|felt| ClassHash(felt.0))
        .map_err(|err| StateError::StateReadError(err.to_string()))
    }

    fn get_compiled_contract_class(&self, class_hash: ClassHash) -> StateResult<ContractClass> {
        Python::with_gil(|py| -> Result<ContractClass, PyErr> {
            let args = (PyFelt::from(class_hash),);
            let py_raw_compiled_class: PyRawCompiledClass = self
                .state_reader_proxy
                .as_ref(py)
                .call_method1("get_raw_compiled_class", args)?
                .extract()?;

            Ok(ContractClass::try_from(py_raw_compiled_class)?)
        })
        .map_err(|err| {
            if Python::with_gil(|py| err.is_instance_of::<UndeclaredClassHashError>(py)) {
                StateError::UndeclaredClassHash(class_hash)
            } else {
                StateError::StateReadError(err.to_string())
            }
        })
    }

    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        Python::with_gil(|py| -> PyResult<PyFelt> {
            let args = (PyFelt::from(class_hash),);
            self.state_reader_proxy
                .as_ref(py)
                .call_method1("get_compiled_class_hash", args)?
                .extract()
        })
        .map(|felt| CompiledClassHash(felt.0))
        .map_err(|err| StateError::StateReadError(err.to_string()))
    }
}

#[derive(FromPyObject)]
pub struct PyRawCompiledClass {
    pub raw_compiled_class: String,
    pub version: usize,
}

impl TryFrom<PyRawCompiledClass> for ContractClass {
    type Error = NativeBlockifierError;

    fn try_from(raw_compiled_class: PyRawCompiledClass) -> NativeBlockifierResult<Self> {
        match raw_compiled_class.version {
            0 => Ok(ContractClassV0::try_from_json_string(&raw_compiled_class.raw_compiled_class)?
                .into()),
            1 => Ok(ContractClassV1::try_from_json_string(&raw_compiled_class.raw_compiled_class)?
                .into()),
            _ => Err(NativeBlockifierInputError::UnsupportedContractClassVersion {
                version: raw_compiled_class.version,
            })?,
        }
    }
}
