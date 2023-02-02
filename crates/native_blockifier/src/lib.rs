use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use starknet_api::StarknetApiError;

pub type NativeBlockifierResult<T> = Result<T, NativeBlockifierError>;

#[pymodule]
fn native_blockifier(_py: Python<'_>, py_module: &PyModule) -> PyResult<()> {
    py_module.add_class::<Storage>()?;

    py_module.add_function(wrap_pyfunction!(test_storage, py_module)?)?;

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
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    StorageError(#[from] papyrus_storage::StorageError),
}

impl From<NativeBlockifierError> for PyErr {
    fn from(err: NativeBlockifierError) -> PyErr {
        PyOSError::new_err(err.to_string())
    }
}
