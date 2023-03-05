use blockifier::transaction::errors::TransactionExecutionError;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use starknet_api::StarknetApiError;

pub type NativeBlockifierResult<T> = Result<T, NativeBlockifierError>;

/// Macro to create NativeBlockifierError variants, their respective Python types, and implements
/// `From<NativeBlockifierError> for PyErr`.
macro_rules! native_blockifier_errors {
    ($(($variant_name:ident, $from_error_type:ty, $py_error_name:ident)),*) => {

        #[derive(thiserror::Error, Debug)]
        pub enum NativeBlockifierError {
            $(
                #[error(transparent)]
                $variant_name(#[from] $from_error_type)
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
                    $(NativeBlockifierError::$variant_name(error) => $py_error_name::new_err(
                        // Constructs with the tuple `(error_code, error_message)`.
                        (
                            String::from("native_blockifier.") + stringify!($py_error_name),
                            format!("{:?}", error),
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
