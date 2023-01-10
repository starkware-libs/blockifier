/// THIS IS A DUMMY FILE!
/// Currently just used as a reference, but once we start the integration all of this should
/// be replaced with real logic.
use std::collections::HashMap;

use pyo3::prelude::*;
use starknet_api::hash::StarkFelt;

#[pyfunction] // can be called from python
fn as_rust_struct(obj: &PyAny) -> PyResult<FromPythonClass> {
    // Calls `obj.get_attr(field)` for every field in FromPythonClass
    let parsed_python_instance: FromPythonClass = obj.extract()?;

    println!("IN RUST: parsed from python: {:?}", &parsed_python_instance);
    Ok(parsed_python_instance)
}

#[pyclass] // can have instances used by Python
#[derive(/* can be parsed from Python */ FromPyObject, Debug)]
pub struct FromPythonClass {
    #[pyo3(get, set)] // allow python to set/get to instances
    pub my_string: String,
}

#[pymethods]
impl FromPythonClass {
    pub fn printer(&self) {
        println!("printer(): {}", self.my_string);
    }
}

#[pyfunction] // can be called from python
fn uses_external_crate() -> PyResult<()> {
    let from_external_crate = StarkFelt::from(3_u64);
    println!("IN RUST: {:?}", from_external_crate);

    Ok(())
}

#[pyclass]
pub struct ComplexStruct {
    #[pyo3(get, set)]
    pub large_vector: Vec<u32>,
    pub dict: HashMap<String, i32>,
}

#[pymethods]
impl ComplexStruct {
    #[new]
    pub fn new(large_vector: Vec<u32>, dict: HashMap<String, i32>) -> Self {
        Self { large_vector, dict }
    }

    pub fn extend_and_sort(&mut self, extension: Vec<u32>) {
        self.large_vector.extend(extension);
        self.large_vector.sort();
    }
}

#[pymodule]
fn rust_extension_poc(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<ComplexStruct>()?;
    m.add_function(wrap_pyfunction!(as_rust_struct, m)?)?;
    m.add_function(wrap_pyfunction!(uses_external_crate, m)?)?;

    Ok(())
}
