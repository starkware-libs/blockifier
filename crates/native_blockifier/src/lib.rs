pub mod errors;
pub mod py_state_diff;
pub mod py_transaction;
pub mod py_transaction_execution_info;
pub mod py_utils;
pub mod storage;

use py_transaction::PyTransactionExecutor;
use py_transaction_execution_info::PyTransactionExecutionInfo;
use pyo3::prelude::*;
use storage::Storage;

use crate::py_state_diff::PyStateDiff;

#[pymodule]
fn native_blockifier(_py: Python<'_>, py_module: &PyModule) -> PyResult<()> {
    py_module.add_class::<PyStateDiff>()?;
    py_module.add_class::<PyTransactionExecutionInfo>()?;
    py_module.add_class::<PyTransactionExecutor>()?;
    py_module.add_class::<Storage>()?;

    Ok(())
}
