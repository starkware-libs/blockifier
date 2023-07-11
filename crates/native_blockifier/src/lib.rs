pub mod errors;
pub mod papyrus_state;
pub mod py_block_executor;
pub mod py_state_diff;
#[cfg(any(feature = "testing", test))]
pub mod py_test_utils;
pub mod py_transaction;
pub mod py_transaction_execution_info;
pub mod py_utils;
pub mod storage;
pub mod transaction_executor;

use errors::add_py_exceptions;
use py_block_executor::PyBlockExecutor;
use py_transaction_execution_info::{
    PyCallInfo, PyOrderedEvent, PyOrderedL2ToL1Message, PyTransactionExecutionInfo,
    PyVmExecutionResources,
};
use pyo3::prelude::*;
use storage::StorageConfig;

use crate::py_state_diff::PyStateDiff;
use crate::py_utils::raise_error_for_testing;

#[pymodule]
fn native_blockifier(py: Python<'_>, py_module: &PyModule) -> PyResult<()> {
    // Initialize Rust-to-Python logging.
    // Usage: just create a Python logger as usual, and it'll capture Rust prints.
    pyo3_log::init();

    py_module.add_class::<PyBlockExecutor>()?;
    py_module.add_class::<PyCallInfo>()?;
    py_module.add_class::<PyOrderedEvent>()?;
    py_module.add_class::<PyOrderedL2ToL1Message>()?;
    py_module.add_class::<PyStateDiff>()?;
    py_module.add_class::<PyTransactionExecutionInfo>()?;
    py_module.add_class::<PyVmExecutionResources>()?;
    py_module.add_class::<StorageConfig>()?;
    add_py_exceptions(py, py_module)?;

    // TODO(Dori, 1/4/2023): If and when supported in the Python build environment, gate this code
    //   with #[cfg(test)].
    py_module.add_function(wrap_pyfunction!(raise_error_for_testing, py)?)?;

    Ok(())
}
