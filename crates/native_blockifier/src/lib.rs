mod py_transaction;
use py_transaction::create_transaction_from_python;
use pyo3::prelude::*;

#[pyfunction]
fn execute_tx(tx: &PyAny) -> PyResult<()> {
    let tx_type: &str = tx.getattr("tx_type")?.getattr("name")?.extract()?;
    let _tx = create_transaction_from_python(tx, tx_type)?;
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
