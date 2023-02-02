use papyrus_storage::db::DbConfig;
use papyrus_storage::{open_storage, StorageReader, StorageWriter};
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use starknet_api::StarknetApiError;

pub type NativeBlockifierResult<T> = Result<T, NativeBlockifierError>;

#[pymodule]
fn native_blockifier(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<Storage>()?;

    m.add_function(wrap_pyfunction!(hello_world, m)?)?;
    m.add_function(wrap_pyfunction!(test_ret_value, m)?)?;
    m.add_function(wrap_pyfunction!(test_storage, m)?)?;
    m.add_function(wrap_pyfunction!(storage, m)?)?;

    Ok(())
}

#[pyclass]
pub struct Storage {
    pub reader: StorageReader,
    pub writer: StorageWriter,
}

// TODO: Add rest of the storage api.
#[pymethods]
impl Storage {}

#[pyfunction]
fn hello_world() {
    println!("Hello from rust.");
}

#[pyfunction]
fn test_ret_value(x: i32, y: i32) -> i32 {
    x + y
}

#[pyfunction]
fn test_storage() -> Storage {
    let (reader, writer) = papyrus_storage::test_utils::get_test_storage();

    Storage { reader, writer }
}

#[pyfunction]
fn storage(path: String) -> NativeBlockifierResult<Storage> {
    let db_config = DbConfig {
        path,
        max_size: 1 << 35, // 32GB.
    };

    let (reader, writer) = open_storage(db_config)?;
    Ok(Storage { reader, writer })
}

#[derive(thiserror::Error, Debug)]
pub enum NativeBlockifierError {
    #[error(transparent)]
    StorageError(#[from] papyrus_storage::StorageError),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    Pyo3Error(#[from] PyErr),
}

impl From<NativeBlockifierError> for PyErr {
    fn from(err: NativeBlockifierError) -> PyErr {
        PyOSError::new_err(err.to_string())
    }
}
