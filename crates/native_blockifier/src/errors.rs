use blockifier::transaction::errors::TransactionExecutionError;
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use starknet_api::StarknetApiError;

pub type NativeBlockifierResult<T> = Result<T, NativeBlockifierError>;

#[derive(thiserror::Error, Debug)]
pub enum NativeBlockifierError {
    #[error(transparent)]
    Pyo3Error(#[from] PyErr),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    TransactionExecutionError(#[from] TransactionExecutionError),
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
