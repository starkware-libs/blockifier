#[cfg(jemalloc)]
// Override default allocator.
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

pub mod errors;
pub mod py_block_executor;
pub mod py_declare;
pub mod py_deploy_account;
pub mod py_invoke_function;
pub mod py_l1_handler;
pub mod py_state_diff;
#[cfg(any(feature = "testing", test))]
pub mod py_test_utils;
// TODO(Dori, 1/4/2023): If and when supported in the Python build environment, use #[cfg(test)].
pub mod py_testing_wrappers;
pub mod py_transaction;
pub mod py_transaction_execution_info;
pub mod py_utils;
pub mod py_validator;
pub mod state_readers;
pub mod storage;
pub mod test_utils;
pub mod transaction_executor;

use errors::{add_py_exceptions, UndeclaredClassHashError};
use py_block_executor::PyBlockExecutor;
use py_transaction_execution_info::{
    PyBouncerInfo, PyCallInfo, PyExecutionResources, PyOrderedEvent, PyOrderedL2ToL1Message,
    PyTransactionExecutionInfo,
};
use py_validator::PyValidator;
use pyo3::prelude::*;
use storage::StorageConfig;

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
    py_module.add_class::<PyBouncerInfo>()?;
    py_module.add_class::<PyCallInfo>()?;
    py_module.add_class::<PyOrderedEvent>()?;
    py_module.add_class::<PyOrderedL2ToL1Message>()?;
    py_module.add_class::<PyStateDiff>()?;
    py_module.add_class::<PyTransactionExecutionInfo>()?;
    py_module.add_class::<PyValidator>()?;
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
