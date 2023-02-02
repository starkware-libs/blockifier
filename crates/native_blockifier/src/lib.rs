mod py_transaction;

use py_transaction::py_tx;
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use starknet_api::StarknetApiError;

pub type NativeBlockifierResult<T> = Result<T, NativeBlockifierError>;

#[pymodule]
fn native_blockifier(_py: Python<'_>, py_module: &PyModule) -> PyResult<()> {
    py_module.add_class::<Storage>()?;

    py_module.add_function(wrap_pyfunction!(execute_tx, py_module)?)?;
    py_module.add_function(wrap_pyfunction!(test_storage, py_module)?)?;

    Ok(())
}

#[pyfunction]
fn execute_tx(tx: &PyAny) -> PyResult<()> {
    let tx_type: &str = tx.getattr("tx_type")?.getattr("name")?.extract()?;
    let _tx = py_tx(tx, tx_type)?;
    Ok(())
}

#[pyclass]
pub struct Storage {
    pub reader: papyrus_storage::StorageReader,
    pub writer: papyrus_storage::StorageWriter,
}

// TODO: Add rest of the storage api.
#[pymethods]
impl Storage {
    #[new]
    pub fn new(path: String) -> NativeBlockifierResult<Storage> {
        let db_config = papyrus_storage::db::DbConfig {
            path,
            max_size: 1 << 35, // 32GB.
        };

        let (reader, writer) = papyrus_storage::open_storage(db_config)?;
        Ok(Storage { reader, writer })
    }
}

#[pyfunction]
fn test_storage() -> Storage {
    let (reader, writer) = papyrus_storage::test_utils::get_test_storage();
    Storage { reader, writer }
}

#[derive(thiserror::Error, Debug)]
pub enum NativeBlockifierError {
    #[error(transparent)]
    Pyo3Error(#[from] PyErr),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    StorageError(#[from] papyrus_storage::StorageError),
}

impl From<NativeBlockifierError> for PyErr {
    fn from(error: NativeBlockifierError) -> PyErr {
        match error {
            NativeBlockifierError::Pyo3Error(py_error) => py_error,
            _ => PyOSError::new_err(error.to_string()),
        }
    }
}
