use blockifier::blockifier::stateful_validator::StatefulValidatorError;
use blockifier::blockifier::transaction_executor::TransactionExecutorError;
use blockifier::bouncer::BuiltinCount;
use blockifier::execution::errors::ContractClassError;
use blockifier::state::errors::StateError;
use blockifier::transaction::errors::{
    ParseError, TransactionExecutionError, TransactionPreValidationError,
};
use blockifier::transaction::transaction_types::TransactionType;
use cairo_vm::types::errors::program_errors::ProgramError;
use num_bigint::BigUint;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use starknet_api::StarknetApiError;
use starknet_types_core::felt::FromStrError;
use thiserror::Error;

pub type NativeBlockifierResult<T> = Result<T, NativeBlockifierError>;

/// Defines `NativeBlockifierError` variants, their respective Python types, and implements a
/// conversion to `PyErr`.
macro_rules! native_blockifier_errors {
    ($(($variant_name:ident, $from_error_type:ty, $py_error_name:ident)),*) => {

        #[derive(Debug, Error)]
        pub enum NativeBlockifierError {
            $(
                #[error(transparent)]
                $variant_name(#[from] $from_error_type)
            ),*
        }

        // Utility method for Python code to know which error types exist.
        #[pyfunction]
        pub fn py_error_names() -> Vec<String> {
            vec![$(String::from(stringify!($py_error_name))),*]
        }

        // Creates new types that implement `Into<PyException>`.
        $(create_exception!(native_blockifier, $py_error_name, PyException);)*

        // Call to register all Python exceptions (and name list getter) in the native_blockifier
        // module.
        pub fn add_py_exceptions(py: Python<'_>, py_module: &PyModule) -> PyResult<()> {
            $(py_module.add(stringify!($py_error_name), py.get_type::<$py_error_name>())?;)*
            py_module.add_function(wrap_pyfunction!(py_error_names, py)?)?;
            Ok(())
        }

        impl From<NativeBlockifierError> for PyErr {
            fn from(error: NativeBlockifierError) -> PyErr {
                match error {
                    $(NativeBlockifierError::$variant_name(error) => $py_error_name::new_err(
                        // Constructs with the tuple `(error_code, error_message)`.
                        (
                            String::from("native_blockifier.") + stringify!($py_error_name),
                            format!("{}", error),
                        )
                    )),*
                }
            }
        }
    };
}

native_blockifier_errors!(
    (ContractClassError, ContractClassError, PyContractClassError),
    (NativeBlockifierInputError, NativeBlockifierInputError, PyNativeBlockifierInputError),
    (ProgramError, ProgramError, PyProgramError),
    (Pyo3Error, PyErr, PyPyo3Error),
    (SerdeError, serde_json::Error, PySerdeError),
    (StarknetApiError, StarknetApiError, PyStarknetApiError),
    (StateError, StateError, PyStateError),
    (StatefulValidatorError, StatefulValidatorError, PyStatefulValidatorError),
    (StorageError, papyrus_storage::StorageError, PyStorageError),
    (TransactionExecutionError, TransactionExecutionError, PyTransactionExecutionError),
    (TransactionExecutorError, TransactionExecutorError, PyTransactionExecutorError),
    (TransactionPreValidationError, TransactionPreValidationError, PyTransactionPreValidationError)
);

#[derive(Debug, Error)]
pub enum NativeBlockifierInputError {
    #[error(transparent)]
    InvalidNativeBlockifierInputError(#[from] InvalidNativeBlockifierInputError),
    #[error(transparent)]
    ParseError(#[from] ParseError),
    #[error(transparent)]
    ProgramError(#[from] ProgramError),
    #[error(transparent)]
    PyFeltParseError(#[from] FromStrError),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error("Unknown builtin: {0}.")]
    UnknownBuiltin(String),
    #[error("Contract class of version {version} is unsupported.")]
    UnsupportedContractClassVersion { version: usize },
    #[error("Transaction of type {tx_type:?} is unsupported in version {version}.")]
    UnsupportedTransactionVersion { tx_type: TransactionType, version: BigUint },
}

#[derive(Debug, Error)]
pub enum InvalidNativeBlockifierInputError {
    #[error("Invalid builtin count: {0:?}.")]
    InvalidBuiltinCounts(BuiltinCount),
    #[error("Invalid Wei gas price: {0}.")]
    InvalidGasPriceWei(u128),
    #[error("Invalid Fri gas price: {0}.")]
    InvalidGasPriceFri(u128),
    #[error("Invalid Wei data gas price: {0}.")]
    InvalidDataGasPriceWei(u128),
    #[error("Invalid Fri data gas price: {0}.")]
    InvalidDataGasPriceFri(u128),
}

create_exception!(native_blockifier, UndeclaredClassHashError, PyException);
