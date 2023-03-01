use std::backtrace::{Backtrace, BacktraceStatus};

use blockifier::transaction::errors::TransactionExecutionError;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use starknet_api::StarknetApiError;

pub type NativeBlockifierResult<T> = Result<T, NativeBlockifierError>;

/// Macro to create NativeBlockifierError variants, their respective Python types, and implements
/// `From<NativeBlockifierError> for PyErr`.
macro_rules! native_blockifier_errors {
    ($(($name:ident, $from_type:ty, $py_error_name:ident)),*) => {
        #[derive(thiserror::Error, Debug)]
        pub enum NativeBlockifierError {
            $(
                #[error("Source error: {source:?}\nBacktrace: {backtrace:?}.")]
                $name {
                    #[from]
                    source: $from_type,
                    backtrace: Backtrace,
                }
            ),*
        }

        // Creates new types that implement `Into<PyException>`.
        $(create_exception!(native_blockifier, $py_error_name, PyException);)*

        // Call to register all python exceptions in the native_blockifier module.
        pub fn add_py_exceptions(py: Python<'_>, py_module: &PyModule) -> PyResult<()> {
            $(py_module.add(stringify!($py_error_name), py.get_type::<$py_error_name>())?;)*
            Ok(())
        }

        impl From<NativeBlockifierError> for PyErr {
            fn from(error: NativeBlockifierError) -> PyErr {
                match error {
                    $(NativeBlockifierError::$name { source, backtrace } => $py_error_name::new_err(
                        // Constructs with the tuple `(error_code, error_message, backtrace)`, where
                        // `backtrace` is `Option<String>`.
                        (
                            String::from("native_blockifier.") + stringify!($py_error_name),
                            format!("{:?}", source),
                            match backtrace.status() {
                                BacktraceStatus::Captured => Some(format!("{:?}", backtrace)),
                                _ => None,
                            }
                        )
                    )),*
                }
            }
        }
    };
}

native_blockifier_errors!(
    (Pyo3Error, PyErr, PyPyo3Error),
    (SerdeError, serde_json::Error, PySerdeError),
    (StarknetApiError, StarknetApiError, PyStarknetApiError),
    (TransactionExecutionError, TransactionExecutionError, PyTransactionExecutionError),
    (StorageError, papyrus_storage::StorageError, PyStorageError)
);
