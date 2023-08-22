use std::error::Error;

use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass;
use blockifier::state::errors::StateError;
use blockifier::state::state_api::{StateReader, StateResult};
use pyo3::exceptions::PyBaseException;
use pyo3::types::{PyModule, PyType};
use pyo3::{pyclass, pymethods, PyAny, PyErr, PyObject, PyResult, Python};
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::errors::{is_undeclared_class_error, UndeclaredClassHashError};
use crate::py_contract_class::PyRawCompiledClass;
use crate::py_utils::{py_enum_name, PyFelt};

pyo3::import_exception!(starkware.starkware_utils.error_handling, StarkException);

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

fn to_state_read_error(e: PyErr) -> StateError {
    // if e.to_string().contains("UNDECLARED_CLASS") {
    //     return StateError::UndeclaredClassHash(ClassHash::default());
    // }
    StateError::StateReadError(e.to_string())
}

// fn to_state_read_error_with_py(e: PyErr, py: Python<'_>) -> PyErr {
//     // let e_type = e.get_type(py).is(PyType::new::<StarkException>(py));
//     // let is_ins = e.is_instance_of::<StarkException>(py);
//     let val = e.value(py).getattr("code").unwrap().getattr("name");
//     // let is_st_e = e.is_instance_of::<StarkException>(py);
//     // let cause = e.cause(py);
//     panic!("string: {:?}, value name: {:?}", e.to_string(), val);
// }

// fn is_undeclared_class_error(err: &PyErr) -> bool {
//     Python::with_gil(|py| {
//         if err.is_instance_of::<StarkException>(py) {
//             let err_code = py_enum_name::<String>(err.value(py), "code").unwrap_or_default();
//             return err_code == "UNDECALRED_CLASS";
//         }
//         false
//     })
// }

impl StateReader for PyStateReader {
    fn get_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        Python::with_gil(|py| -> Result<StarkFelt, PyErr> {
            let args = (0, PyFelt::from(contract_address), PyFelt(*key.0.key())); // TODO: implement PyFelt::from<StorageKey>
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
                0,
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
        Python::with_gil(|py| -> StateResult<ContractClass> {
            let args = (PyFelt::from(*class_hash),);
            let result: PyRawCompiledClass = self
                .py_state_reader
                .as_ref(py)
                .call_method1("get_raw_compiled_class", args)
                .map_err(|err| {
                    if err.is_instance_of::<UndeclaredClassHashError>(py) {
                        StateError::UndeclaredClassHash(*class_hash)
                    } else {
                        StateError::StateReadError(err.to_string())
                    }
                })?
                .extract()
                .map_err(|err| StateError::StateReadError(err.to_string()))?;
            // .map_err(|e| to_state_read_error_with_py(e, py))?

            ContractClass::try_from(result)
                .map_err(|err| StateError::StateReadError(err.to_string()))
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
        .map_err(to_state_read_error)
    }

    // fn get_fee_token_balance(
    //     &mut self,
    //     block_context: &BlockContext,
    //     contract_address: &ContractAddress,
    // ) -> Result<(StarkFelt, StarkFelt), StateError> {
    //     Python::with_gil(|py| -> Result<(StarkFelt, StarkFelt), PyErr> {
    //         let args = (
    //             PyModule::import(py, "starkware.starknet.business_logic.state.storage_domain")?
    //                 .call_method1("StorageDomain", (0,))?,
    //             PyFelt::from(*contract_address),
    //             PyFelt::from(block_context.fee_token_address),
    //         );
    //         let result: (PyFelt, PyFelt) = self
    //             .py_state_reader
    //             .as_ref(py)
    //             .call_method1("get_fee_token_balance", args)?
    //             .extract()?;

    //         Ok((result.0.0, result.1.0))
    //     })
    //     .map_err(to_state_read_error)
    // }
}
