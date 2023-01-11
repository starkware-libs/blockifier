use pyo3::prelude::*;

#[pyfunction]
fn hello_world() {
    println!("Hello from rust.");
}

#[pymodule]
fn python_rust_bridge(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello_world, m)?)?;

    Ok(())
}
