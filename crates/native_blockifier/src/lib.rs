mod py_transaction;

use py_transaction::py_tx;
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use starknet_api::StarknetApiError;

pub type NativeBlockifierResult<T> = Result<T, NativeBlockifierError>;

#[pyfunction]
fn execute_tx(tx: &PyAny) -> PyResult<()> {
    let tx_type: &str = tx.getattr("tx_type")?.getattr("name")?.extract()?;
    let _tx = py_tx(tx, tx_type)?;
    Ok(())
}

#[pyfunction]
fn hello_world() {
    println!("Hello from rust.");
}

#[pyfunction]
fn test_ret_value(x: i32, y: i32) -> i32 {
    x + y
}

#[pymodule]
fn native_blockifier(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello_world, m)?)?;
    m.add_function(wrap_pyfunction!(test_ret_value, m)?)?;
    m.add_function(wrap_pyfunction!(execute_tx, m)?)?;

    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub enum NativeBlockifierError {
    #[error(transparent)]
    Pyo3Error(#[from] PyErr),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
}

impl From<NativeBlockifierError> for PyErr {
    fn from(error: NativeBlockifierError) -> PyErr {
        match error {
            NativeBlockifierError::Pyo3Error(py_error) => py_error,
            _ => PyOSError::new_err(error.to_string()),
        }
    }
}
