#![feature(error_generic_member_access)]
#![feature(provide_any)]

pub mod errors;
pub mod py_state_diff;
pub mod py_test_utils;
pub mod py_transaction;
pub mod py_transaction_execution_info;
pub mod py_utils;
pub mod storage;

use errors::add_py_exceptions;
use py_transaction::PyTransactionExecutor;
use py_transaction_execution_info::{
    PyCallInfo, PyExecutionResources, PyOrderedEvent, PyOrderedL2ToL1Message,
    PyTransactionExecutionInfo,
};
use pyo3::prelude::*;
use storage::Storage;

use crate::py_state_diff::PyStateDiff;

#[pymodule]
fn native_blockifier(_py: Python<'_>, py_module: &PyModule) -> PyResult<()> {
    py_module.add_class::<PyCallInfo>()?;
    py_module.add_class::<PyExecutionResources>()?;
    py_module.add_class::<PyOrderedEvent>()?;
    py_module.add_class::<PyOrderedL2ToL1Message>()?;
    py_module.add_class::<PyStateDiff>()?;
    py_module.add_class::<PyTransactionExecutionInfo>()?;
    py_module.add_class::<PyTransactionExecutor>()?;
    py_module.add_class::<Storage>()?;
    add_py_exceptions(_py, py_module)?;

    Ok(())
}
