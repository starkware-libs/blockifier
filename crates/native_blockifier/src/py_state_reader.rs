use std::error::Error;

use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass;
use blockifier::state::errors::StateError;
use blockifier::state::state_api::{StateReader, StateResult};
use pyo3::types::PyModule;
use pyo3::{pyclass, pymethods, PyAny, PyErr, PyObject, Python};
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::py_contract_class::PyCompiledClassBase;
use crate::py_utils::PyFelt;

#[pyclass]
pub struct PyStateReader {
    py_state_reader: PyObject,
}

#[pymethods]
impl PyStateReader {
    #[new]
    #[args(py_state_reader)]
    pub fn new(py_state_reader: &PyAny) -> Self {
        // TODO: input validations
        Self { py_state_reader: PyObject::from(py_state_reader) }
    }
}

fn to_state_read_error(e: impl Error) -> StateError {
    StateError::StateReadError(e.to_string())
}

impl StateReader for PyStateReader {
    fn get_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        Python::with_gil(|py| -> Result<StarkFelt, PyErr> {
            let args = (PyFelt::from(contract_address), PyFelt(*key.0.key())); // TODO: implement PyFelt::from<StorageKey>
            let result: PyFelt =
                self.py_state_reader.as_ref(py).call_method1("get_storage_at", args)?.extract()?;

            Ok(result.0)
        })
        .map_err(to_state_read_error)
    }

    fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce> {
        Python::with_gil(|py| -> Result<Nonce, PyErr> {
            let args = (
                // TODO: is there a better way?
                PyModule::import(py, "starkware.starknet.business_logic.state.storage_domain")?
                    .call_method1("StorageDomain", (0,))?,
                PyFelt::from(contract_address),
            );
            let result: PyFelt =
                self.py_state_reader.as_ref(py).call_method1("get_nonce_at", args)?.extract()?;

            Ok(Nonce(result.0))
        })
        .map_err(to_state_read_error)
    }

    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        Python::with_gil(|py| -> Result<ClassHash, PyErr> {
            log::debug!("PyState get_class_hash_at...");
            let args = (PyFelt::from(contract_address),);
            let result: PyFelt = self
                .py_state_reader
                .as_ref(py)
                .call_method1("get_class_hash_at", args)?
                .extract()?;

            Ok(ClassHash(result.0))
        })
        .map_err(to_state_read_error)
    }

    fn get_compiled_contract_class(
        &mut self,
        class_hash: &ClassHash,
    ) -> StateResult<ContractClass> {
        Python::with_gil(|py| -> Result<ContractClass, PyErr> {
            let args = (PyFelt::from(*class_hash),);
            let result: PyCompiledClassBase = self
                .py_state_reader
                .as_ref(py)
                .call_method1("get_compiled_class", args)?
                .extract()?;

            Ok(ContractClass::try_from(result)?)
        })
        .map_err(to_state_read_error)
    }

    fn get_compiled_class_hash(&mut self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        Python::with_gil(|py| -> Result<CompiledClassHash, PyErr> {
            let args = (PyFelt::from(class_hash),);
            let result: PyFelt = self
                .py_state_reader
                .as_ref(py)
                .call_method1("get_compiled_class_hash", args)?
                .extract()?;

            Ok(CompiledClassHash(result.0))
        })
        .map_err(to_state_read_error)
    }

    fn get_fee_token_balance(
        &mut self,
        block_context: &BlockContext,
        contract_address: &ContractAddress,
    ) -> Result<(StarkFelt, StarkFelt), StateError> {
        Python::with_gil(|py| -> Result<(StarkFelt, StarkFelt), PyErr> {
            let args = (
                PyModule::import(py, "starkware.starknet.business_logic.state.storage_domain")?
                    .call_method1("StorageDomain", (0,))?,
                PyFelt::from(*contract_address),
                PyFelt::from(block_context.fee_token_address),
            );
            let result: (PyFelt, PyFelt) = self
                .py_state_reader
                .as_ref(py)
                .call_method1("get_fee_token_balance", args)?
                .extract()?;

            Ok((result.0.0, result.1.0))
        })
        .map_err(to_state_read_error)
    }
}
