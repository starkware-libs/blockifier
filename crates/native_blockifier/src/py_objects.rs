use std::collections::HashMap;

use blockifier::abi::constants;
use blockifier::blockifier::config::ConcurrencyConfig;
use blockifier::bouncer::{BouncerConfig, BouncerWeights, BuiltinCount};
use blockifier::versioned_constants::VersionedConstants;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

// From Rust to Python.

#[pyclass]
#[derive(Clone, Default)]
pub struct PyExecutionResources {
    #[pyo3(get)]
    pub n_steps: usize,
    #[pyo3(get)]
    pub builtin_instance_counter: HashMap<String, usize>,
    #[pyo3(get)]
    pub n_memory_holes: usize,
}

impl From<ExecutionResources> for PyExecutionResources {
    fn from(resources: ExecutionResources) -> Self {
        Self {
            n_steps: resources.n_steps,
            builtin_instance_counter: resources.builtin_instance_counter,
            n_memory_holes: resources.n_memory_holes,
        }
    }
}

// From Python to Rust.

#[pyclass]
#[derive(Clone)]
pub struct PyVersionedConstantsOverrides {
    pub validate_max_n_steps: u32,
    pub max_recursion_depth: usize,
    pub private_versioned_constants: Option<String>,
}

#[pymethods]
impl PyVersionedConstantsOverrides {
    #[new]
    #[pyo3(signature = (validate_max_n_steps, max_recursion_depth, private_versioned_constants))]
    pub fn create(
        validate_max_n_steps: u32,
        max_recursion_depth: usize,
        private_versioned_constants: Option<String>,
    ) -> Self {
        Self { validate_max_n_steps, max_recursion_depth, private_versioned_constants }
    }

    #[staticmethod]
    pub fn validate_private_versioned_constants_str(
        private_versioned_constants: &str,
    ) -> PyResult<()> {
        if serde_json::from_str::<VersionedConstants>(private_versioned_constants).is_ok() {
            Ok(())
        } else {
            Err(PyValueError::new_err("Failed to parse private_versioned_constants."))
        }
    }
}

#[derive(Clone, Debug, FromPyObject)]
pub struct PyBouncerConfig {
    pub full_total_weights_with_keccak: HashMap<String, usize>,
    pub full_total_weights: HashMap<String, usize>,
}

impl From<PyBouncerConfig> for BouncerConfig {
    fn from(py_bouncer_config: PyBouncerConfig) -> Self {
        BouncerConfig {
            block_max_capacity: hash_map_into_bouncer_weights(
                py_bouncer_config.full_total_weights.clone(),
            ),
            block_max_capacity_with_keccak: hash_map_into_bouncer_weights(
                py_bouncer_config.full_total_weights_with_keccak.clone(),
            ),
        }
    }
}

fn hash_map_into_bouncer_weights(mut data: HashMap<String, usize>) -> BouncerWeights {
    BouncerWeights {
        gas: data.remove(constants::L1_GAS_USAGE).expect("gas_weight must be present"),
        n_steps: data.remove(constants::N_STEPS_RESOURCE).expect("n_steps must be present"),
        message_segment_length: data
            .remove(constants::MESSAGE_SEGMENT_LENGTH)
            .expect("message_segment_length must be present"),
        state_diff_size: data
            .remove(constants::STATE_DIFF_SIZE)
            .expect("state_diff_size must be present"),
        n_events: data.remove(constants::N_EVENTS).expect("n_events must be present"),
        builtin_count: BuiltinCount::from(data),
    }
}

#[derive(Debug, Default, FromPyObject)]
pub struct PyConcurrencyConfig {
    pub enabled: bool,
    pub n_workers: usize,
    pub chunk_size: usize,
}

impl From<PyConcurrencyConfig> for ConcurrencyConfig {
    fn from(py_concurrency_config: PyConcurrencyConfig) -> Self {
        ConcurrencyConfig {
            enabled: py_concurrency_config.enabled,
            n_workers: py_concurrency_config.n_workers,
            chunk_size: py_concurrency_config.chunk_size,
        }
    }
}
