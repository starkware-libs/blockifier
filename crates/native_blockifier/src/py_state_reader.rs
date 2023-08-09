use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass;
use blockifier::state::errors::StateError;
use blockifier::state::state_api::{StateReader, StateResult};
use pyo3::{PyAny, PyErr, PyObject, Python};
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::errors::is_undeclared_class_error;
use crate::py_contract_class::PyRawCompiledClass;
use crate::py_utils::{on_chain_storage_domain, PyFelt};

pub struct PyStateReader {
    py_state_reader: PyObject,
}

impl PyStateReader {
    pub fn new(py_state_reader: &PyAny) -> Self {
        Self { py_state_reader: PyObject::from(py_state_reader) }
    }
}

impl StateReader for PyStateReader {
    fn get_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        Python::with_gil(|py| -> Result<StarkFelt, PyErr> {
            let args =
                (on_chain_storage_domain(py)?, PyFelt::from(contract_address), PyFelt::from(key));
            let result: PyFelt =
                self.py_state_reader.as_ref(py).call_method1("get_storage_at", args)?.extract()?;

            Ok(result.0)
        })
        .map_err(|err| StateError::StateReadError(err.to_string()))
    }

    fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce> {
        Python::with_gil(|py| -> Result<Nonce, PyErr> {
            let args = (on_chain_storage_domain(py)?, PyFelt::from(contract_address));
            let result: PyFelt =
                self.py_state_reader.as_ref(py).call_method1("get_nonce_at", args)?.extract()?;

            Ok(Nonce(result.0))
        })
        .map_err(|err| StateError::StateReadError(err.to_string()))
    }

    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        Python::with_gil(|py| -> Result<ClassHash, PyErr> {
            let args = (PyFelt::from(contract_address),);
            let result: PyFelt = self
                .py_state_reader
                .as_ref(py)
                .call_method1("get_class_hash_at", args)?
                .extract()?;

            Ok(ClassHash(result.0))
        })
        .map_err(|err| StateError::StateReadError(err.to_string()))
    }

    fn get_compiled_contract_class(
        &mut self,
        class_hash: &ClassHash,
    ) -> StateResult<ContractClass> {
        Python::with_gil(|py| -> Result<ContractClass, PyErr> {
            let args = (PyFelt::from(*class_hash),);
            let result: PyRawCompiledClass = self
                .py_state_reader
                .as_ref(py)
                .call_method1("get_raw_compiled_class", args)?
                .extract()?;

            Ok(ContractClass::try_from(result)?)
        })
        .map_err(|err| {
            if is_undeclared_class_error(&err) {
                StateError::UndeclaredClassHash(*class_hash)
            } else {
                StateError::StateReadError(err.to_string())
            }
        })
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
        .map_err(|err| StateError::StateReadError(err.to_string()))
    }

    fn get_fee_token_balance(
        &mut self,
        block_context: &BlockContext,
        contract_address: &ContractAddress,
    ) -> Result<(StarkFelt, StarkFelt), StateError> {
        Python::with_gil(|py| -> Result<(StarkFelt, StarkFelt), PyErr> {
            let args = (
                on_chain_storage_domain(py)?,
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
        .map_err(|err| StateError::StateReadError(err.to_string()))
    }
}
