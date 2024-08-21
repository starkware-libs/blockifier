// The blockifier crate supports only these specific architectures.
#![cfg(any(target_pointer_width = "16", target_pointer_width = "32", target_pointer_width = "64",))]

pub mod errors;
pub mod py_block_executor;
pub mod py_declare;
pub mod py_deploy_account;
pub mod py_invoke_function;
pub mod py_l1_handler;
pub mod py_objects;
pub mod py_state_diff;
#[cfg(any(feature = "testing", test))]
pub mod py_test_utils;
// TODO(Dori, 1/4/2023): If and when supported in the Python build environment, use #[cfg(test)].
pub mod py_testing_wrappers;
pub mod py_transaction;
pub mod py_utils;
pub mod py_validator;
pub mod state_readers;
pub mod storage;
pub mod test_utils;

use errors::{add_py_exceptions, UndeclaredClassHashError};
use py_block_executor::PyBlockExecutor;
use py_objects::PyExecutionResources;
use py_validator::PyValidator;
use pyo3::prelude::*;
use storage::StorageConfig;

use crate::py_objects::PyVersionedConstantsOverrides;
use crate::py_state_diff::PyStateDiff;
use crate::py_testing_wrappers::{
    estimate_casm_hash_computation_resources_for_testing_list,
    estimate_casm_hash_computation_resources_for_testing_single, raise_error_for_testing,
};

#[pymodule]
fn native_blockifier(py: Python<'_>, py_module: &PyModule) -> PyResult<()> {
    // Initialize Rust-to-Python logging.
    // Usage: just create a Python logger as usual, and it'll capture Rust prints.
    pyo3_log::init();

    py_module.add_class::<PyBlockExecutor>()?;
    py_module.add_class::<PyStateDiff>()?;
    py_module.add_class::<PyValidator>()?;
    py_module.add_class::<PyVersionedConstantsOverrides>()?;
    py_module.add_class::<PyExecutionResources>()?;
    py_module.add_class::<StorageConfig>()?;
    py_module.add("UndeclaredClassHashError", py.get_type::<UndeclaredClassHashError>())?;
    add_py_exceptions(py, py_module)?;

    py_module.add_function(wrap_pyfunction!(blockifier_version, py)?)?;

    // TODO(Dori, 1/4/2023): If and when supported in the Python build environment, gate this code
    //   with #[cfg(test)].
    py_module.add_function(wrap_pyfunction!(raise_error_for_testing, py)?)?;
    py_module.add_function(wrap_pyfunction!(
        estimate_casm_hash_computation_resources_for_testing_list,
        py
    )?)?;
    py_module.add_function(wrap_pyfunction!(
        estimate_casm_hash_computation_resources_for_testing_single,
        py
    )?)?;

    Ok(())
}

/// Returns the version that the `blockifier` and `native_blockifier` crates were built with.
// Assumption: both `blockifier` and `native_blockifier` use `version.workspace` in the package
// section of their `Cargo.toml`.
#[pyfunction]
pub fn blockifier_version() -> PyResult<String> {
    Ok(env!("CARGO_PKG_VERSION").to_string())
}
